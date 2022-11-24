<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine\CacheStorage;

use CrowdSec\RemediationEngine\Constants;
use CrowdSec\RemediationEngine\Decision;
use IPLib\Address\Type;
use IPLib\Factory;
use IPLib\Range\RangeInterface;
use IPLib\Range\Subnet;
use Monolog\Handler\NullHandler;
use Monolog\Logger;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Symfony\Component\Cache\Adapter\TagAwareAdapterInterface;
use Symfony\Component\Cache\PruneableInterface;

abstract class AbstractCache
{
    /** @var string Cache symbol */
    public const CACHE_SEP = '_';
    /** @var string Internal name for deferred cache item */
    public const DEFER = 'deferred';
    /** @var string Internal name for effective saved cache item (not deferred) */
    public const DONE = 'done';
    /** @var int Cache item content array main value index */
    public const INDEX_MAIN = 0;
    /** @var string The cache key prefix for a IPV4 range bucket */
    public const IPV4_BUCKET_KEY = 'range_bucket_ipv4';
    /** @var string Cache tag for remediation */
    private const CACHE_TAG_REM = 'remediation';
    /** @var int Cache item content array expiration index */
    private const INDEX_EXP = 1;
    /** @var int Cache item content array identifier index */
    private const INDEX_ID = 2;
    /** @var int The size of ipv4 range cache bucket */
    private const IPV4_BUCKET_SIZE = 256;
    /** @var string The cache tag for range bucket cache item */
    private const RANGE_BUCKET_TAG = 'range_bucket';
    /** @var AdapterInterface */
    protected $adapter;
    /**
     * @var array
     */
    protected $configs;
    /**
     * @var LoggerInterface
     */
    protected $logger;
    /**
     * @var array
     */
    private $cacheKeys = [];

    public function __construct(array $configs, AdapterInterface $adapter, LoggerInterface $logger = null)
    {
        $this->configs = $configs;
        $this->adapter = $adapter;
        if (!$logger) {
            $logger = new Logger('null');
            $logger->pushHandler(new NullHandler());
        }
        $this->logger = $logger;
    }

    public function cleanCachedValues(array $cachedValues): array
    {
        foreach ($cachedValues as $key => $cachedValue) {
            // Remove expired value
            $currentTime = time();
            if ($currentTime > $cachedValue[self::INDEX_EXP]) {
                unset($cachedValues[$key]);
            }
        }

        return $cachedValues;
    }

    /**
     * Deletes all items in the pool.
     */
    public function clear(): bool
    {
        return $this->adapter->clear();
    }

    /**
     * Persists any deferred cache items.
     */
    public function commit(): bool
    {
        return $this->adapter->commit();
    }

    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * Cache key convention.
     *
     * @throws CacheException
     */
    public function getCacheKey(string $scope, string $value): string
    {
        if (!isset($this->cacheKeys[$scope][$value])) {
            switch ($scope) {
                case Constants::SCOPE_IP:
                case Constants::SCOPE_RANGE:
                case self::IPV4_BUCKET_KEY:
                    $result = $scope . self::CACHE_SEP . $value;
                    break;
                default:
                    throw new CacheException('Unknown scope:' . $scope);
            }

            /**
             * Replace unauthorized symbols.
             *
             * @see https://symfony.com/doc/current/components/cache/cache_items.html#cache-item-keys-and-values
             */
            $this->cacheKeys[$scope][$value] = preg_replace('/[^A-Za-z0-9_.]/', self::CACHE_SEP, $result);
        }

        return $this->cacheKeys[$scope][$value];
    }

    /**
     * Retrieve a config value by name. Return null if no set.
     *
     * @param string $name
     * @return mixed
     */
    public function getConfig(string $name)
    {
        return (isset($this->configs[$name])) ? $this->configs[$name] : null;
    }

    /**
     * @throws InvalidArgumentException
     */
    public function getItem(string $cacheKey): CacheItemInterface
    {
        return $this->adapter->getItem(base64_encode($cacheKey));
    }

    /**
     * Prune (delete) of all expired cache items.
     *
     * @throws CacheException
     */
    public function prune(): bool
    {
        if ($this->adapter instanceof PruneableInterface) {
            return $this->adapter->prune();
        }

        throw new CacheException('Cache Adapter ' . \get_class($this->adapter) . ' can not be pruned.');
    }

    /**
     * @throws InvalidArgumentException|CacheException|\Psr\Cache\CacheException
     */
    public function removeDecision(Decision $decision): array
    {
        $result = [self::DONE => 0, self::DEFER => 0];
        switch ($decision->getScope()) {
            case Constants::SCOPE_IP:
                $result = $this->remove($decision);
                break;
            case Constants::SCOPE_RANGE:
                $result = $this->handleRangeScoped($decision, [$this, 'remove']);
                break;
            default:
                $this->logger->warning('', [
                    'type' => 'CACHE_REMOVE_NON_IMPLEMENTED_SCOPE',
                    'decision' => $decision->toArray(),
                ]);
                break;
        }

        return $result;
    }

    /**
     * @throws InvalidArgumentException|CacheException
     *
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     */
    public function retrieveDecisionsForIp(string $scope, string $ip): array
    {
        $cachedDecisions = [];
        switch ($scope) {
            case Constants::SCOPE_IP:
                $cacheKey = $this->getCacheKey($scope, $ip);
                $item = $this->getItem($cacheKey);
                if ($item->isHit()) {
                    $cachedDecisions[] = $item->get();
                }
                break;
            case Constants::SCOPE_RANGE:
                $bucketInt = $this->getRangeIntForIp($ip);
                $bucketCacheKey = $this->getCacheKey(self::IPV4_BUCKET_KEY, (string) $bucketInt);
                $bucketItem = $this->getItem($bucketCacheKey);
                $cachedBuckets = $bucketItem->isHit() ? $bucketItem->get() : [];
                foreach ($cachedBuckets as $cachedBucket) {
                    $rangeString = $cachedBucket[self::INDEX_MAIN];
                    $address = Factory::parseAddressString($ip);
                    $range = Factory::parseRangeString($rangeString);
                    if ($address && $range && $range->contains($address)) {
                        $cacheKey = $this->getCacheKey(Constants::SCOPE_RANGE, $rangeString);
                        $item = $this->getItem($cacheKey);
                        if ($item->isHit()) {
                            $cachedDecisions[] = $item->get();
                        }
                    }
                }
                break;
            default:
                $this->logger->warning('', [
                    'type' => 'CACHE_RETRIEVE_FOR_IP_NON_IMPLEMENTED_SCOPE',
                    'scope' => $scope,
                ]);
                break;
        }

        return $cachedDecisions;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->adapter->saveDeferred($item);
    }

    /**
     * @throws CacheException
     * @throws InvalidArgumentException|\Psr\Cache\CacheException
     */
    public function storeDecision(Decision $decision): array
    {
        $result = [self::DONE => 0, self::DEFER => 0];
        switch ($decision->getScope()) {
            case Constants::SCOPE_IP:
                $result = $this->store($decision);
                break;
            case Constants::SCOPE_RANGE:
                $result = $this->handleRangeScoped($decision, [$this, 'store']);
                break;
            default:
                $this->logger->warning('', [
                    'type' => 'CACHE_STORE_NON_IMPLEMENTED_SCOPE',
                    'decision' => $decision->toArray(),
                ]);
        }

        return $result;
    }

    /**
     * Format decision to use a minimal amount of data (less cache data consumption).
     *
     * @throws \Exception
     */
    private function format(Decision $decision, ?int $bucketInt = null): array
    {
        $mainValue = $bucketInt ? $decision->getValue() : $decision->getType();

        return [
            self::INDEX_MAIN => $mainValue,
            self::INDEX_EXP => $decision->getExpiresAt(),
            self::INDEX_ID => $decision->getIdentifier(),
        ];
    }

    /**
     * Check if some identifier is already cached.
     */
    private function getCachedIndex(string $identifier, array $cachedValues): ?int
    {
        $result = array_search($identifier, array_column($cachedValues, self::INDEX_ID), true);

        return false === $result ? null : $result;
    }

    private function getMaxExpiration(array $itemsToCache): int
    {
        $exps = array_column($itemsToCache, self::INDEX_EXP);
        return $exps ? max($exps) : 0;
    }

    /**
     * @throws CacheException
     */
    private function getRangeIntForIp(string $ip): int
    {
        $ipInt = ip2long($ip);
        if (false === $ipInt) {
            // @codeCoverageIgnoreStart
            throw new CacheException("$ip is not a valid IpV4 address");
            // @codeCoverageIgnoreEnd
        }
        try {
            $result = intdiv($ipInt, self::IPV4_BUCKET_SIZE);
            // @codeCoverageIgnoreStart
        } catch (\ArithmeticError | \DivisionByZeroError $e) {
            throw new CacheException('Something went wrong during integer division: ' . $e->getMessage());
            // @codeCoverageIgnoreEnd
        }

        return $result;
    }

    /**
     * @return array|string[]
     */
    private function getTags(Decision $decision, ?int $bucketInt = null): array
    {
        return $bucketInt ? [self::RANGE_BUCKET_TAG] : [self::CACHE_TAG_REM, $decision->getScope()];
    }

    /**
     * @return int[]
     *
     * @throws CacheException
     */
    private function handleRangeScoped(Decision $decision, callable $method): array
    {
        $range = $this->manageRange($decision);
        if (!$range) {
            return [self::DONE => 0, self::DEFER => 0];
        }
        $startAddress = $range->getStartAddress();
        $endAddress = $range->getEndAddress();

        $startInt = $this->getRangeIntForIp($startAddress->toString());
        $endInt = $this->getRangeIntForIp($endAddress->toString());
        for ($i = $startInt; $i <= $endInt; ++$i) {
            call_user_func_array($method, [$decision, $i]);
        }

        return call_user_func_array($method, [$decision]);
    }

    /**
     * @SuppressWarnings(PHPMD.StaticAccess)
     */
    private function manageRange(Decision $decision): ?RangeInterface
    {
        $rangeString = $decision->getValue();
        $range = Subnet::parseString($rangeString);
        if (null === $range) {
            $this->logger->error('', [
                'type' => 'INVALID_RANGE',
                'decision' => $decision->toArray(),
            ]);

            return null;
        }
        $addressType = $range->getAddressType();
        if (Type::T_IPv6 === $addressType) {
            $this->logger->warning('', [
                'type' => 'IPV6_RANGE_NOT_IMPLEMENTED',
                'decision' => $decision->toArray(),
            ]);

            return null;
        }

        return $range;
    }

    /**
     * @throws CacheException
     * @throws InvalidArgumentException
     * @throws \Exception|\Psr\Cache\CacheException
     *
     * @noinspection PhpSameParameterValueInspection
     */
    private function remove(Decision $decision, ?int $bucketInt = null): array
    {
        $result = [self::DONE => 0, self::DEFER => 0];
        $cacheKey = $bucketInt ? $this->getCacheKey(self::IPV4_BUCKET_KEY, (string) $bucketInt) :
            $this->getCacheKey($decision->getScope(), $decision->getValue());
        $item = $this->getItem($cacheKey);

        if ($item->isHit()) {
            $cachedValues = $item->get();
            $indexToRemove = $this->getCachedIndex($decision->getIdentifier(), $cachedValues);
            // Early return if not in cache
            if (null === $indexToRemove) {
                return $result;
            }
            unset($cachedValues[$indexToRemove]);
            $cachedValues = $this->cleanCachedValues($cachedValues);
            if (!$cachedValues) {
                $result[self::DONE] = (int) $this->adapter->deleteItem(base64_encode($cacheKey));

                return $result;
            }
            $tags = $this->getTags($decision, $bucketInt);
            $item = $this->updateCacheItem($item, $cachedValues, $tags);
            $result[self::DEFER] = 1;
            if (!$this->saveDeferred($item)) {
                $this->logger->warning('', [
                    'type' => 'CACHE_STORE_DEFERRED_FAILED_FOR_REMOVE_DECISION',
                    'decision' => $decision->toArray(),
                    'bucket_int' => $bucketInt,
                ]);
                $result[self::DEFER] = 0;
            }
        }

        return $result;
    }

    /**
     * @return int[]
     *
     * @throws CacheException
     * @throws InvalidArgumentException
     * @throws \Exception|\Psr\Cache\CacheException
     *
     * @noinspection PhpSameParameterValueInspection
     */
    private function store(Decision $decision, ?int $bucketInt = null): array
    {
        $cacheKey = $bucketInt ? $this->getCacheKey(self::IPV4_BUCKET_KEY, (string) $bucketInt) :
            $this->getCacheKey($decision->getScope(), $decision->getValue());
        $item = $this->getItem($cacheKey);
        $cachedValues = $item->isHit() ? $item->get() : [];
        $indexToStore = $this->getCachedIndex($decision->getIdentifier(), $cachedValues);
        if (null !== $indexToStore) {
            return [self::DONE => 0, self::DEFER => 0];
        }
        $cachedValues = $this->cleanCachedValues($cachedValues);

        // Merge current value with cached values (if any).
        $currentValue = $this->format($decision, $bucketInt);
        $decisionsToCache = array_merge($cachedValues, [$currentValue]);
        // Rebuild cache item
        $item = $this->updateCacheItem($item, $decisionsToCache, $this->getTags($decision, $bucketInt));

        $result = [self::DONE => 0, self::DEFER => 1];
        if (!$this->saveDeferred($item)) {
            $this->logger->warning('', [
                'type' => 'CACHE_STORE_DEFERRED_FAILED',
                'decision' => $decision->toArray(),
                'bucket_int' => $bucketInt,
            ]);
            $result[self::DEFER] = 0;
        }

        return $result;
    }

    /**
     * @throws InvalidArgumentException
     * @throws \Exception|\Psr\Cache\CacheException
     *
     * @SuppressWarnings(PHPMD.MissingImport)
     */
    private function updateCacheItem(CacheItemInterface $item, array $valuesToCache, array $tags): CacheItemInterface
    {
        $maxExpiration = $this->getMaxExpiration($valuesToCache);
        $item->set($valuesToCache);
        $item->expiresAt(new \DateTime('@' . $maxExpiration));
        if ($this->adapter instanceof TagAwareAdapterInterface) {
            $item->tag($tags);
        }

        return $item;
    }
}
