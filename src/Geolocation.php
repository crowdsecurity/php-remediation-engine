<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine;

use CrowdSec\RemediationEngine\CacheStorage\AbstractCache;
use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use Psr\Log\LoggerInterface;

class Geolocation
{
    /**
     * @var array
     */
    private $configs;
    /**
     * @var AbstractCache
     */
    private $cacheStorage;
    /**
     * @var LoggerInterface
     */
    private $logger;
    /**
     * @var string[]
     */
    private $geolocTemplate = ['country' => '', 'not_found' => '', 'error' => ''];
    /**
     * @var array
     */
    private $maxmindCountryResult = [];

    public function __construct(
        array $configs,
        AbstractCache $cacheStorage,
        LoggerInterface $logger
    ) {
        $this->configs = $configs;
        $this->cacheStorage = $cacheStorage;
        $this->logger = $logger;
    }


    public function handleCountryResultForIp(string $ip, int $cacheDuration): array
    {
        $result = $this->geolocTemplate;
        $saveInCache = !empty($this->configs['save_result']);
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
        if (Constants::GEOLOCATION_TYPE_MAXMIND !== $this->configs['type']) {
            throw new RemediationException('Unknown Geolocation type:' . $this->configs['type']);
        }
        $configPath = $this->configs[Constants::GEOLOCATION_TYPE_MAXMIND];
        $result = $this->getMaxMindCountryResult($ip, $configPath['database_type'], $configPath['database_path']);

        if ($saveInCache) {
            if (!empty($result['country'])) {
                $this->cacheStorage->setIpVariables(
                    AbstractCache::GEOLOCATION,
                    ['crowdsec_geolocation_country' => $result['country']],
                    $ip,
                    $cacheDuration,
                    AbstractCache::GEOLOCATION
                );
            } elseif (!empty($result['not_found'])) {
                $this->cacheStorage->setIpVariables(
                    AbstractCache::GEOLOCATION,
                    ['crowdsec_geolocation_not_found' => $result['not_found']],
                    $ip,
                    $cacheDuration,
                    AbstractCache::GEOLOCATION
                );
            }
        }

        return $result;

    }

    /**
     * Retrieve a country from a MaxMind database.
     *
     * @throws \Exception
     */
    private function getMaxMindCountryResult(string $ip, string $databaseType, string $databasePath): array
    {
        if (!isset($this->maxmindCountryResult[$ip][$databaseType][$databasePath])) {
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

            $this->maxmindCountryResult[$ip][$databaseType][$databasePath] = $result;
        }

        return $this->maxmindCountryResult[$ip][$databaseType][$databasePath];
    }
}
