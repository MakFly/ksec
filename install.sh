#!/bin/sh
# Installe ksec depuis les releases GitHub.
#
#   curl -fsSL https://raw.githubusercontent.com/dev-toolings/ksec/master/install.sh | sh
#
# Variables :
#   KSEC_VERSION          version précise (défaut : la dernière release)
#   KSEC_INSTALL_DIR      répertoire d'installation (défaut : ~/.local/bin)
#   KSEC_ONLY_IF_NEWER    =1 pour ne rien faire si la version visée est déjà
#                         installée — c'est ce qui rend ce script rejouable
#                         sans frais depuis un timer (voir scripts/autoupdate/).
#
# CE SCRIPT VÉRIFIE LA SOMME SHA-256 AVANT D'INSTALLER, ET S'ARRÊTE SI ELLE NE
# CORRESPOND PAS. Un installeur qu'on canalise dans un shell exécute du code
# arrivé par le réseau ; le minimum qu'il doive à celui qui le lance, c'est de
# prouver que l'octet posé sur son disque est bien celui qui a été publié.
set -eu

REPO="dev-toolings/ksec"
BINARY="ksec"
INSTALL_DIR="${KSEC_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() {
	printf '\n✗ %s\n' "$*" >&2
	exit 1
}

# ── Outils ────────────────────────────────────────────────────────────────────

have() { command -v "$1" >/dev/null 2>&1; }

if have curl; then
	fetch() { curl -fsL "$1" -o "$2" 2>/dev/null; }
	fetch_stdout() { curl -fsL "$1" 2>/dev/null; }
elif have wget; then
	fetch() { wget -qO "$2" "$1" 2>/dev/null; }
	fetch_stdout() { wget -qO- "$1" 2>/dev/null; }
else
	die "ni curl ni wget — impossible de télécharger quoi que ce soit."
fi

if have sha256sum; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif have shasum; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die "ni sha256sum ni shasum — la somme de contrôle ne peut pas être vérifiée,
  et installer sans la vérifier n'est pas proposé par ce script."
fi

# ── Plateforme ────────────────────────────────────────────────────────────────

os="$(uname -s)"
arch="$(uname -m)"

case "$os/$arch" in
Linux/x86_64 | Linux/amd64) target="linux-x86_64" ;;
Linux/aarch64 | Linux/arm64) target="linux-aarch64" ;;
Darwin/x86_64 | Darwin/amd64) target="darwin-x86_64" ;;
Darwin/aarch64 | Darwin/arm64) target="darwin-aarch64" ;;
*)
	die "plateforme non publiée : $os/$arch

  Les releases couvrent linux/x86_64, linux/aarch64, darwin/x86_64 et
  darwin/aarch64. Pour tout le reste, la compilation depuis les sources :

    git clone https://github.com/$REPO.git && cd $BINARY && cargo install --path ."
	;;
esac

# ── Version ───────────────────────────────────────────────────────────────────

version="${KSEC_VERSION:-}"
if [ -z "$version" ]; then
	say "→ recherche de la dernière release de $REPO"
	version="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
	[ -n "$version" ] || die "aucune release trouvée pour $REPO."
fi

asset="${BINARY}-${target}"
base="https://github.com/$REPO/releases/download/$version"

# Rejoué chaque jour par un timer, ce script téléchargerait le binaire pour
# réécrire le même octet. `ksec --version` imprime « ksec 0.1.0 » ; le second
# champ suffit à trancher. On compare des chaînes (le tag « v0.1.0 » sans son
# « v »), pas des numéros : on ne cherche pas « plus récent », seulement « autre
# chose que ce qui tourne ».
if [ "${KSEC_ONLY_IF_NEWER:-}" = "1" ] && [ -x "$INSTALL_DIR/$BINARY" ]; then
	installed="$("$INSTALL_DIR/$BINARY" --version 2>/dev/null | awk '{print $2}')"
	[ -n "$installed" ] || installed="absent"
	if [ "$installed" = "${version#v}" ]; then
		say "→ ksec $version déjà installé — rien à faire"
		exit 0
	fi
	say "→ ksec ${installed} → $version"
fi

say "→ ksec $version ($target)"

# ── Téléchargement et vérification ────────────────────────────────────────────

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "→ téléchargement"
fetch "$base/$asset" "$tmp/$asset" ||
	die "téléchargement impossible : $base/$asset

  Cette version publie-t-elle bien un binaire pour $target ?"
fetch "$base/$asset.sha256" "$tmp/$asset.sha256" ||
	die "somme .sha256 introuvable pour $version — installation refusée.

  Sans elle, rien ne distingue le binaire publié d'un fichier substitué en route."

expected="$(grep -F " $asset" "$tmp/$asset.sha256" | cut -d' ' -f1 | head -1)"
[ -n "$expected" ] || die "$asset n'apparaît pas dans son fichier .sha256 — installation refusée."

actual="$(sha256 "$tmp/$asset")"
if [ "$expected" != "$actual" ]; then
	die "SOMME DE CONTRÔLE INVALIDE — rien n'a été installé.

  attendue  $expected
  obtenue   $actual

  Soit le téléchargement a été corrompu, soit le fichier n'est pas celui qui a
  été publié. Recommence ; si l'écart persiste, ne l'installe pas."
fi
say "  ✓ SHA-256 vérifiée"

# ── Installation ──────────────────────────────────────────────────────────────

mkdir -p "$INSTALL_DIR"
chmod 0755 "$tmp/$asset"
# On écrit à côté puis on déplace : un binaire remplacé pendant qu'il tourne ne
# doit jamais être un fichier à moitié écrit.
mv "$tmp/$asset" "$INSTALL_DIR/$BINARY.new"
mv "$INSTALL_DIR/$BINARY.new" "$INSTALL_DIR/$BINARY"
say "  ✓ $INSTALL_DIR/$BINARY"

got="$("$INSTALL_DIR/$BINARY" --version)" || die "le binaire installé ne s'exécute pas."
say "  ✓ $got"

# ── Suite ─────────────────────────────────────────────────────────────────────

case ":$PATH:" in
*":$INSTALL_DIR:"*) ;;
*)
	say ""
	say "⚠ $INSTALL_DIR n'est pas dans ton PATH. Ajoute :"
	say ""
	say "    export PATH=\"\$PATH:$INSTALL_DIR\""
	;;
esac
