filename="$1"

lines=$(wc -l < "$filename")
words=$(wc -w < "$filename")
characters=$(wc -c < "$filename")

[ "$lines" -lt 3 ] && [ "$words" -gt 1000 ] && [ "$characters" -gt 2000 ] && echo "The file is suspicious" || echo "The file is not suspicious"