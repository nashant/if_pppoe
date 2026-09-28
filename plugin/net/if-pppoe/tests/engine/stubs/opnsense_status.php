<?php

/*
 * Minimal stand-ins for the core classes IfPppoeStatus uses, copied in shape from
 * opnsense/core 25.7.11 (src/opnsense/mvc/app/library/OPNsense/System/AbstractStatus.php,
 * SystemStatusCode.php); Backend returns canned configd output.
 */

namespace OPNsense\System {

    enum SystemStatusCode: int
    {
        case ERROR = -1;
        case WARNING = 0;
        case NOTICE = 1;
        case OK = 2;
    }

    abstract class AbstractStatus
    {
        protected $internalPriority = 100;
        protected $internalPersistent = false;
        protected $internalIsBanner = false;
        protected $internalTitle = null;
        protected $internalMessage = null;
        protected $internalLocation = null;
        protected $internalStatus = SystemStatusCode::OK;
        protected $internalTimestamp = null;
        protected $internalScope = [];

        public function getPersistent()
        {
            return $this->internalPersistent;
        }

        public function getTitle()
        {
            return $this->internalTitle;
        }

        public function getStatus()
        {
            return $this->internalStatus;
        }

        public function getMessage()
        {
            return $this->internalMessage ?? 'No problems were detected.';
        }

        public function getLocation()
        {
            return $this->internalLocation;
        }

        public function getTimestamp()
        {
            return $this->internalTimestamp;
        }

        public function collectStatus()
        {
        }
    }
}

namespace OPNsense\Core {

    final class Backend
    {
        public static string $reply = '';
        public static array $calls = [];

        public function configdRun($event, $detach = false, $timeout = 120, $connect_timeout = 10)
        {
            self::$calls[] = $event;
            return self::$reply;
        }
    }
}

namespace {

    if (!function_exists('gettext')) {
        function gettext($s)
        {
            return $s;
        }
    }
}
