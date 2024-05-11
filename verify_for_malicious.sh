filename="$1"

if grep -q -i -e "corrupted" -e "dangerous" -e "risk" -e "attack" -e "malware" -e "malicious" "$filename"; then
    echo 1
    exit 1
fi

if [[ $(tr -d '[:print:]' < "$filename" | wc -c) -gt 0 ]]; then
    echo 1
    exit 1
fi

echo 0
exit 0