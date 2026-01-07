FROM gcc:13
WORKDIR /app
COPY main.c /app/main.c
CMD sh -lc 'set -eu; \
	out_dir="${OUT_DIR:-out}"; \
	mkdir -p "$out_dir"; \
	if [ -n "${TEXT:-}" ]; then \
		val="$TEXT"; \
	else \
		if [ -z "${SEED:-}" ]; then echo "Missing TEXT or SEED" >&2; exit 2; fi; \
		n=$(printf "%s" "$SEED" | cksum | awk "{print \$1}"); \
		a=$((n % 256)); \
		b=$(( (n / 256) % 256 )); \
		c=$(( (n / 65536) % 256 )); \
		d=$(( (n / 16777216) % 256 )); \
		val="10.$a.$b.$c-$d"; \
	fi; \
	# Keep header generation simple: reject characters that would break the C string literal.
	case "$val" in \
		*\\\\*|*\"*) echo "TEXT contains unsupported characters" >&2; exit 2 ;; \
	esac; \
	printf "#define HIDDEN_TEXT \"%s\"\\n" "$val" > /app/generated.h; \
	gcc -O2 -o "$out_dir/hiddenbin" /app/main.c; \
	"$out_dir/hiddenbin"'
