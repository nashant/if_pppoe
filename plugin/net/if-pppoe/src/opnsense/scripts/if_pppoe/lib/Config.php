<?php

/*
 * Copyright (c) 2026 os-if-pppoe contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace IfPppoe\Engine;

/**
 * Read-only view of /conf/config.xml, converted the way core's
 * OPNsense\Core\Config::toArray() does (element text as string, repeated
 * tags as lists), so presence tests match core's isset() semantics.
 * Core never writes a false boolean: Config::fromArray() skips it
 * (Config.php:215 at 25.7.11), so "element present" == "flag set".
 */
final class Config
{
    private array $data;

    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public static function fromFile(string $file): self
    {
        if (!is_readable($file)) {
            throw new \RuntimeException("cannot read {$file}");
        }
        $prev = libxml_use_internal_errors(true);
        $xml = simplexml_load_file($file, 'SimpleXMLElement', LIBXML_NONET | LIBXML_COMPACT);
        libxml_use_internal_errors($prev);
        if ($xml === false) {
            throw new \RuntimeException("cannot parse {$file}");
        }
        return new self(self::toArray($xml));
    }

    public static function fromString(string $xml): self
    {
        $prev = libxml_use_internal_errors(true);
        $x = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_COMPACT);
        libxml_use_internal_errors($prev);
        if ($x === false) {
            throw new \RuntimeException('cannot parse config xml');
        }
        return new self(self::toArray($x));
    }

    private static function toArray(\SimpleXMLElement $node)
    {
        $groups = [];
        foreach ($node->children() as $name => $child) {
            $groups[$name][] = $child->count() > 0 ? self::toArray($child) : (string)$child;
        }
        $out = [];
        foreach ($groups as $name => $values) {
            $out[$name] = count($values) > 1 ? $values : $values[0];
        }
        return $out;
    }

    public function raw(): array
    {
        return $this->data;
    }

    /** @return list of values for a tag that may appear once or many times */
    private static function listOf($v): array
    {
        if ($v === null || $v === '') {
            return [];
        }
        if (is_array($v) && array_is_list($v)) {
            return $v;
        }
        return [$v];
    }

    /** friendly => interface config array */
    public function interfaces(): array
    {
        $ifs = $this->data['interfaces'] ?? [];
        return is_array($ifs) ? $ifs : [];
    }

    public function iface(string $friendly): ?array
    {
        $ifs = $this->interfaces();
        return isset($ifs[$friendly]) && is_array($ifs[$friendly]) ? $ifs[$friendly] : null;
    }

    /** list of <ppps><ppp> arrays */
    public function ppps(): array
    {
        $out = [];
        foreach (self::listOf($this->data['ppps']['ppp'] ?? null) as $p) {
            if (is_array($p)) {
                $out[] = $p;
            }
        }
        return $out;
    }

    public function pppByDevice(string $device): ?array
    {
        foreach ($this->ppps() as $p) {
            if (($p['if'] ?? null) === $device) {
                return $p;
            }
        }
        return null;
    }

    /** friendly name(s) assigned to $device */
    public function friendlyForDevice(string $device): ?string
    {
        foreach ($this->interfaces() as $name => $cfg) {
            if (is_array($cfg) && ($cfg['if'] ?? null) === $device) {
                return (string)$name;
            }
        }
        return null;
    }

    public function dnsAllowOverride(): bool
    {
        return !empty($this->data['system']['dnsallowoverride']);
    }

    public function ipv6Allowed(): bool
    {
        return isset($this->data['system']['ipv6allow']);
    }

    /** reason string when CARP VIPs or HA sync are configured, else null */
    public function haReason(): ?string
    {
        foreach (self::listOf($this->data['virtualip']['vip'] ?? null) as $vip) {
            if (is_array($vip) && ($vip['mode'] ?? '') === 'carp') {
                return 'CARP virtual IPs are configured (HA is not supported)';
            }
        }
        $ha = $this->data['hasync'] ?? null;
        if (is_array($ha)) {
            foreach (['pfsyncinterface', 'synchronizetoip', 'pfsyncpeerip'] as $k) {
                if (!empty($ha[$k])) {
                    return "high availability is configured (hasync/{$k})";
                }
            }
        }
        return null;
    }

    /** plugin model OPNsense/IfPppoe/general */
    public function pluginSettings(): array
    {
        $g = $this->data['OPNsense']['IfPppoe']['general'] ?? [];
        $g = is_array($g) ? $g : [];
        $exclude = [];
        foreach (explode(',', (string)($g['exclude'] ?? '')) as $e) {
            $e = trim($e);
            if ($e !== '') {
                $exclude[] = $e;
            }
        }
        return [
            'enabled' => ($g['enabled'] ?? '0') === '1',
            'exclude' => $exclude,
        ];
    }

    /** resolve a <ppp><ports> entry the way get_real_interface() would for PPPoE */
    public function realInterface(string $port): string
    {
        $cfg = $this->iface($port);
        if ($cfg !== null && !empty($cfg['if'])) {
            return (string)$cfg['if'];
        }
        return $port;
    }
}
