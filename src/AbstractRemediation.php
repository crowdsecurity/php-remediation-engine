<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine;

use CrowdSec\RemediationEngine\CacheStorage\AbstractCache;
use CrowdSec\RemediationEngine\CacheStorage\CacheException;
use Monolog\Handler\NullHandler;
use Monolog\Logger;
use Psr\Cache\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;

abstract class AbstractRemediation
{
    /** @var string The CrowdSec name for deleted decisions */
    public const CS_DEL = 'deleted';
    /** @var string The CrowdSec name for new decisions */
    public const CS_NEW = 'new';
    /** @var string Priority index */
    public const INDEX_PRIO = 'priority';
    /**
     * @var AbstractCache
     */
    protected $cacheStorage;
    /**
     * @var array
     */
    protected $configs;
    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var string[]
     */
    private $geolocTemplate = ['country' => '', 'not_found' => '', 'error' => ''];

    public function __construct(array $configs, AbstractCache $cacheStorage, LoggerInterface $logger = null)
    {
        $this->configs = $configs;
        $this->cacheStorage = $cacheStorage;
        if (!$logger) {
            $logger = new Logger('null');
            $logger->pushHandler(new NullHandler());
        }
        $this->logger = $logger;
    }

    /**
     * Clear cache.
     */
    public function clearCache(): bool
    {
        return $this->cacheStorage->clear();
    }

    /**
     * Retrieve a config by name.
     *
     * @return mixed|null
     */
    public function getConfig(string $name)
    {
        return (isset($this->configs[$name])) ? $this->configs[$name] : null;
    }

    /**
     * Retrieve remediation for some IP.
     */
    abstract public function getIpRemediation(string $ip): string;

    /**
     * Prune cache.
     *
     * @throws CacheStorage\CacheException
     */
    public function pruneCache(): bool
    {
        return $this->cacheStorage->prune();
    }

    /**
     * Pull fresh decisions and update the cache.
     * Return the total of added and removed records. // ['new' => x, 'deleted' => y].
     */
    abstract public function refreshDecisions(): array;

    protected function convertRawDecisionsToDecisions(array $rawDecisions): array
    {
        $decisions = [];
        foreach ($rawDecisions as $rawDecision) {
            $decision = $this->convertRawDecision($rawDecision);
            if ($decision) {
                $decisions[] = $decision;
            }
        }

        return $decisions;
    }

    protected function getAllCachedDecisions(string $ip): array
    {
        // Ask cache for Ip scoped decision
        $ipDecisions = $this->cacheStorage->retrieveDecisionsForIp(Constants::SCOPE_IP, $ip);
        // Ask cache for Range scoped decision
        $rangeDecisions = $this->cacheStorage->retrieveDecisionsForIp(Constants::SCOPE_RANGE, $ip);
        // Ask cache for Country scoped decision
        // @TODO : depends on configs
                // @TODO
                /**
                 * Check if IP geolocalized country is cached
                 * If not : - get related country from Maxmind (depends on config)
                 *          - if config, store related country
                 * If yes : keep this country
                 * Then : check if there is cached item for this country
                 */
        $geolocConfig = $this->getConfig('geolocation')??[];
        $countryDecisions = [];
        if(!empty($geolocConfig['enabled'])){
            $countryResult = $this->handleCountryResultForIp($geolocConfig, $ip);
            if(!empty($countryResult['country'])){
                $countryDecisions = $this->cacheStorage->retrieveDecisionsForCountry($countryResult['country']);
            }
        }

        return array_merge(
            !empty($ipDecisions[AbstractCache::STORED]) ? $ipDecisions[AbstractCache::STORED] : [],
            !empty($rangeDecisions[AbstractCache::STORED]) ? $rangeDecisions[AbstractCache::STORED] : [],
            !empty($countryDecisions[AbstractCache::STORED]) ? $countryDecisions[AbstractCache::STORED] : []
        );
    }

    protected function getRemediationFromDecisions(array $decisions): string
    {
        $cleanDecisions = $this->cacheStorage->cleanCachedValues($decisions);

        $sortedDecisions = $this->sortDecisionsByRemediationPriority($cleanDecisions);

        // Return only a remediation with the highest priority
        return $sortedDecisions[0][AbstractCache::INDEX_MAIN] ?? Constants::REMEDIATION_BYPASS;
    }

    /**
     * Remove decisions from cache.
     *
     * @throws CacheException
     * @throws InvalidArgumentException|\Psr\Cache\CacheException
     */
    protected function removeDecisions(array $decisions): array
    {
        if (!$decisions) {
            return [AbstractCache::DONE => 0, AbstractCache::REMOVED => []];
        }
        $deferCount = 0;
        $doneCount = 0;
        $removed = [];
        foreach ($decisions as $decision) {
            $removeResult = $this->cacheStorage->removeDecision($decision);
            $deferCount += $removeResult[AbstractCache::DEFER];
            $doneCount += $removeResult[AbstractCache::DONE];
            if (!empty($removeResult[AbstractCache::REMOVED])) {
                $removed[] = $removeResult[AbstractCache::REMOVED];
            }
        }

        return [
            AbstractCache::DONE => $doneCount + ($this->cacheStorage->commit() ? $deferCount : 0),
            AbstractCache::REMOVED => $removed,
        ];
    }

    /**
     * Sort the decision array of a cache item, by remediation priorities.
     */
    protected function sortDecisionsByRemediationPriority(array $decisions): array
    {
        if (!$decisions) {
            return $decisions;
        }
        // Add priorities
        $orderedRemediations = (array) $this->getConfig('ordered_remediations');
        $fallback = $this->getConfig('fallback_remediation');
        $decisionsWithPriority = [];
        foreach ($decisions as $decision) {
            $priority = array_search($decision[AbstractCache::INDEX_MAIN], $orderedRemediations);
            // Use fallback for unknown remediation
            if (false === $priority) {
                $priority = array_search($fallback, $orderedRemediations);
                $decision[AbstractCache::INDEX_MAIN] = $fallback;
            }
            $decision[self::INDEX_PRIO] = $priority;
            $decisionsWithPriority[] = $decision;
        }
        // Sort by priorities.
        /** @var callable $compareFunction */
        $compareFunction = self::class . '::comparePriorities';
        usort($decisionsWithPriority, $compareFunction);

        return $decisionsWithPriority;
    }

    /**
     * Add decisions in cache.
     *
     * @throws CacheException
     * @throws InvalidArgumentException|\Psr\Cache\CacheException
     */
    protected function storeDecisions(array $decisions): array
    {
        if (!$decisions) {
            return [AbstractCache::DONE => 0, AbstractCache::STORED => []];
        }
        $deferCount = 0;
        $doneCount = 0;
        $stored = [];
        foreach ($decisions as $decision) {
            $storeResult = $this->cacheStorage->storeDecision($decision);
            $deferCount += $storeResult[AbstractCache::DEFER];
            $doneCount += $storeResult[AbstractCache::DONE];
            if (!empty($storeResult[AbstractCache::STORED])) {
                $stored[] =  $storeResult[AbstractCache::STORED];
            }
        }

        return [
            AbstractCache::DONE => $doneCount + ($this->cacheStorage->commit() ? $deferCount : 0),
            AbstractCache::STORED => $stored,
        ];
    }

    /**
     * Compare two priorities.
     *
     * @noinspection PhpUnusedPrivateMethodInspection
     *
     * @SuppressWarnings(PHPMD.UnusedPrivateMethod)
     */
    private static function comparePriorities(array $a, array $b): int
    {
        $a = $a[self::INDEX_PRIO];
        $b = $b[self::INDEX_PRIO];
        if ($a == $b) {
            return 0;
        }

        return ($a < $b) ? -1 : 1;
    }

    private function convertRawDecision(array $rawDecision): ?Decision
    {
        if (!$this->validateRawDecision($rawDecision)) {
            return null;
        }
        // The existence of the following indexes must be guaranteed by the validateRawDecision method
        $value = $rawDecision['value'];
        $type = $rawDecision['type'];
        $origin = $rawDecision['origin'];
        $duration = $rawDecision['duration'];
        $scope = $this->handleDecisionScope($rawDecision['scope']);

        return new Decision(
            $this->handleDecisionIdentifier($origin, $type, $scope, $value),
            $scope,
            $value,
            $type,
            $origin,
            $this->handleDecisionExpiresAt($type, $duration)
        );
    }

    /**
     * Retrieve a country from a MaxMind database.
     *
     * @throws Exception
     */
    private function getMaxMindCountry(string $ip, string $databaseType, string $databasePath): array
    {
        if (!isset($this->maxmindCountry[$ip][$databaseType][$databasePath])) {
            $result = $this->geolocTemplate;
            try {
                $reader = new Reader($databasePath);
                switch ($databaseType) {
                    case Constants::MAXMIND_COUNTRY:
                        $record = $reader->country($ip);
                        break;
                    case Constants::MAXMIND_CITY:
                        $record = $reader->city($ip);
                        break;
                    default:
                        throw new RemediationException("Unknown MaxMind database type:$databaseType");
                }
                $result['country'] = $record->country->isoCode;
            } catch (AddressNotFoundException $e) {
                $result['not_found'] = $e->getMessage();
            } catch (\Exception $e) {
                $result['error'] = $e->getMessage();
            }

            $this->maxmindCountry[$ip][$databaseType][$databasePath] = $result;
        }

        return $this->maxmindCountry[$ip][$databaseType][$databasePath];
    }

    private function handleCountryResultForIp(array $geolocConfig, string $ip): array
    {
        $result = $this->geolocTemplate;
        $saveInCache = !empty($geolocConfig['save_result']);
        if ($saveInCache) {
            $cachedVariables = $this->cacheStorage->getIpVariables(
                AbstractCache::GEOLOCATION,
                ['crowdsec_geolocation_country', 'crowdsec_geolocation_not_found'],
                $ip
            );
            $country = $cachedVariables['crowdsec_geolocation_country'] ?? null;
            $notFoundError = $cachedVariables['crowdsec_geolocation_not_found'] ?? null;
            if ($country) {
                $result['country'] = $country;

                return $result;
            } elseif ($notFoundError) {
                $result['not_found'] = $notFoundError;

                return $result;
            }
        }
        if (Constants::GEOLOCATION_TYPE_MAXMIND !== $geolocConfig['type']) {
            throw new RemediationException('Unknown Geolocation type:' . $geolocConfig['type']);
        }
        $configPath = $geolocConfig[Constants::GEOLOCATION_TYPE_MAXMIND];
        $result = $this->getMaxMindCountry($ip, $configPath['database_type'], $configPath['database_path']);

        if ($saveInCache) {
            if (!empty($result['country'])) {
                $this->cacheStorage->setIpVariables(
                    AbstractCache::GEOLOCATION,
                    ['crowdsec_geolocation_country' => $result['country']],
                    $ip,
                    (int) $this->getConfig('geolocation_cache_duration'),
                    AbstractCache::GEOLOCATION
                );
            } elseif (!empty($result['not_found'])) {
                $this->cacheStorage->setIpVariables(
                    AbstractCache::GEOLOCATION,
                    ['crowdsec_geolocation_not_found' => $result['not_found']],
                    $ip,
                    (int) $this->getConfig('geolocation_cache_duration'),
                    AbstractCache::GEOLOCATION
                );
            }
        }

        return $result;

    }

    private function handleDecisionExpiresAt(string $type, string $duration): int
    {
        switch ($type) {
            case Constants::REMEDIATION_BYPASS:
                $duration = $this->getConfig('clean_ip_cache_duration');
                break;
            default:
                $duration = $this->parseDurationToSeconds($duration);
                if (!$this->getConfig('stream_mode')) {
                    $duration = min((int) $this->getConfig('bad_ip_cache_duration'), $duration);
                }
                break;
        }

        return time() + (int) $duration;
    }

    private function handleDecisionIdentifier(
        string $origin,
        string $type,
        string $scope,
        string $value
    ): string {
        return
            $origin . Decision::ID_SEP .
            $type . Decision::ID_SEP .
            $this->handleDecisionScope($scope) . Decision::ID_SEP .
            $value;
    }

    private function handleDecisionScope(string $scope): string
    {
        return strtolower($scope);
    }

    private function parseDurationToSeconds(string $duration): int
    {
        /**
         * 3h24m59.5565s or 3h24m5957ms or 149h, etc.
         */
        $re = '/(-?)(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)(?:\.\d+)?(m?)s)?/m';
        preg_match($re, $duration, $matches);
        if (empty($matches[0])) {
            $this->logger->error('', [
                'type' => 'DECISION_DURATION_PARSE_ERROR',
                'duration' => $duration,
            ]);

            return 0;
        }
        $seconds = 0;
        if (isset($matches[2])) {
            $seconds += ((int) $matches[2]) * 3600; // hours
        }
        if (isset($matches[3])) {
            $seconds += ((int) $matches[3]) * 60; // minutes
        }
        $secondsPart = 0;
        if (isset($matches[4])) {
            $secondsPart += ((int) $matches[4]); // seconds
        }
        if (isset($matches[5]) && 'm' === $matches[5]) { // units in milliseconds
            $secondsPart *= 0.001;
        }
        $seconds += $secondsPart;
        if ('-' === $matches[1]) { // negative
            $seconds *= -1;
        }

        return (int) round($seconds);
    }

    private function validateRawDecision(array $rawDecision): bool
    {
        if (
            isset(
                $rawDecision['scope'],
                $rawDecision['value'],
                $rawDecision['type'],
                $rawDecision['origin'],
                $rawDecision['duration']
            )
        ) {
            return true;
        }

        $this->logger->warning('', [
            'type' => 'RAW_DECISION_NOT_AS_EXPECTED',
            'raw_decision' => json_encode($rawDecision),
        ]);

        return false;
    }
}
