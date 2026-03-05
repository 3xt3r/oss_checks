# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class RenamedFile:
    src: Path
    dst: Path


# Плейсхолдеры, которые НЕ должны встречаться в координатах проекта (G/A/V):
#   - ${...}
#   - \${...}
#   - @...@ (resource filtering / archetype templates)
_GAV_PLACEHOLDER_RE = re.compile(
    r"<(groupId|artifactId|version)>\s*(\\?\$\{[^}]+\}|@[^@]+@)\s*</\1>",
    re.IGNORECASE,
)


def is_template_pom(pom_path: Path) -> bool:
    """
    Шаблонный pom.xml = в КООРДИНАТАХ проекта (groupId/artifactId/version)
    есть плейсхолдеры.
    Мы НЕ считаем шаблоном обычные ${...} в <properties>/<dependencies>,
    поэтому анализируем только "шапку" файла.
    """
    try:
        txt = pom_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    # Режем до секций, чтобы не ловить ${...} в зависимостях
    head = txt
    for cut_tag in ("<dependencies", "<dependencyManagement", "<build", "<profiles", "<modules"):
        idx = head.find(cut_tag)
        if idx != -1:
            head = head[:idx]
            break

    return bool(_GAV_PLACEHOLDER_RE.search(head))


def hide_template_poms(root: Path, suffix: str = ".__tmpl__") -> list[RenamedFile]:
    """
    Временно переименовывает шаблонные pom.xml -> pom.xml{suffix}.
    Возвращает список переименований для восстановления.
    """
    renamed: list[RenamedFile] = []

    for pom in root.rglob("pom.xml"):
        if not pom.is_file():
            continue

        if is_template_pom(pom):
            dst = pom.with_name(pom.name + suffix)

            # безопасно: если dst уже есть — не трогаем
            if dst.exists():
                print(f"[SKIP] template pom already hidden: {pom.relative_to(root)}")
                continue

            try:
                pom.rename(dst)
                renamed.append(RenamedFile(src=pom, dst=dst))
                print(f"[HIDE] template pom: {pom.relative_to(root)}")
            except Exception as ex:
                print(f"[WARN] failed to hide {pom}: {ex}")

    print(f"[INFO] hidden template pom.xml files: {len(renamed)}")
    return renamed


def restore_hidden_poms(renamed: list[RenamedFile], root: Path) -> None:
    """
    Возвращает pom.xml{suffix} обратно в pom.xml.
    """
    restored = 0
    for item in renamed:
        try:
            if item.dst.exists() and not item.src.exists():
                item.dst.rename(item.src)
                restored += 1
                print(f"[RESTORE] {item.src.relative_to(root)}")
        except Exception as ex:
            print(f"[WARN] failed to restore {item.dst}: {ex}")

    print(f"[INFO] restored template pom.xml files: {restored}")

