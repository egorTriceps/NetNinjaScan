from typing import List

from svscan.scanners.network_scanner import expand_targets as expand_targets_from_scanner


def expand_targets(targets: List[str]) -> List[str]:
    return expand_targets_from_scanner(targets)