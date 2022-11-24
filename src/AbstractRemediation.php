<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine;

use CrowdSec\RemediationEngine\CacheStorage\AbstractCache;
use CrowdSec\RemediationEngine\CacheStorage\CacheException;
use Monolog\Handler\NullHandler;
use Monolog\Logger;
use Psr\Cache\InvalidArgumentException;
use Psr\Log\LoggerInterface;

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

    /**
     * Remove decisions from cache.
     *
     * @throws CacheException
     * @throws InvalidArgumentException|\Psr\Cache\CacheException
     */
    public function removeDecisions(array $decisions): int
    {
        if (!$decisions) {
            return 0;
        }
        $deferCount = 0;
        $doneCount = 0;
        foreach ($decisions as $decision) {
            $removeResult = $this->cacheStorage->removeDecision($decision);
            $deferCount += $removeResult[AbstractCache::DEFER];
            $doneCount += $removeResult[AbstractCache::DONE];
        }

        return $doneCount + ($this->cacheStorage->commit() ? $deferCount : 0);
    }

    /**
     * Add decisions in cache.
     *
     * @throws CacheException
     * @throws InvalidArgumentException|\Psr\Cache\CacheException
     */
    public function storeDecisions(array $decisions): int
    {
        $result = 0;
        if (!$decisions) {
            return $result;
        }
        $deferCount = 0;
        $doneCount = 0;
        foreach ($decisions as $decision) {
            $storeResult = $this->cacheStorage->storeDecision($decision);
            $deferCount += $storeResult[AbstractCache::DEFER];
            $doneCount += $storeResult[AbstractCache::DONE];
        }

        return $doneCount + ($this->cacheStorage->commit() ? $deferCount : 0);
    }

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
        // The id index exists for raw LAPI decisions but not for CAPI ones
        $id = $rawDecision['id'] ?? 0;

        return new Decision(
            $this->handleDecisionIdentifier($origin, $type, $scope, $value, $id),
            $scope,
            $value,
            $type,
            $origin,
            $this->handleDecisionExpiresAt($type, $duration)
        );
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
        string $value,
        int $id
    ): string {
        if ($id > 0) {
            return (string) $id;
        }

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
