<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine\Logger;

use CrowdSec\Common\Logger\FileLog as CommonFileLog;

/**
 * A Monolog logger implementation with 2 files : debug and prod.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 *
 * @deprecated since 1.1.0: Use CrowdSec\Common\Logger\FileLog instead
 *
 * @todo remove in 2.0.0
 *
 */
class FileLog extends CommonFileLog
{
    /**
     * @var string The logger name
     */
    public const LOGGER_NAME = 'remediation-engine-logger';
}
