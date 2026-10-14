# Invoked by the remote account's shell. Only public algorithm/blob are substituted.
set -eu
umask 077
for utility in awk mkdir chmod sleep rmdir; do
    command -v "$utility" >/dev/null 2>&1 || exit 69
done
[ -n "${HOME:-}" ] && [ -d "$HOME" ] || exit 70
cd "$HOME" || exit 70
[ ! -L .ssh ] || exit 70
if [ -e .ssh ]; then [ -d .ssh ] || exit 70; else mkdir .ssh || exit 70; fi
chmod 700 .ssh || exit 70
cd .ssh || exit 70
[ ! -L .sshelter-deploy-lock ] || exit 70
attempt=0
until mkdir .sshelter-deploy-lock 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 5 ] || exit 75
    sleep 1
done
trap 'rmdir .sshelter-deploy-lock 2>/dev/null || :' 0
trap 'exit 74' 1 2 3 15
[ ! -L authorized_keys ] || exit 70
if [ -e authorized_keys ]; then
    [ -f authorized_keys ] || exit 70
else
    : > authorized_keys || exit 70
fi
chmod 600 authorized_keys || exit 70
# Tokenize the first three fields while retaining quoted options as a single field.
# Never match a key in a comment or inside command="...".
if awk -v algorithm='__ALGORITHM__' -v blob='__BLOB__' '
function token(    c, word, quoted, escaped) {
    while (pos <= length($0) && substr($0,pos,1) ~ /[ \t]/) pos++
    word=""; quoted=0; escaped=0
    while (pos <= length($0)) {
        c=substr($0,pos,1)
        if (!quoted && !escaped && c ~ /[ \t]/) break
        word=word c; pos++
        if (escaped) escaped=0
        else if (c == "\\") escaped=1
        else if (c == "\"") quoted=!quoted
    }
    return word
}
{
    # Normalize only the in-memory record used for parsing; never rewrite the file.
    sub(/\r$/, "")
    pos=1; first=token()
    if (first == "" || substr(first,1,1) == "#") next
    second=token(); third=token()
    if ((first == algorithm && second == blob) || (second == algorithm && third == blob)) found=1
}
END { exit !found }
' authorized_keys; then
    printf 'SSHELTER_PRESENT\n'
else
    status=$?
    [ "$status" -eq 1 ] || exit 70
    # Preserve an unterminated last line; an additional empty line is harmless.
    if [ -s authorized_keys ]; then printf '\n' >> authorized_keys || exit 70; fi
    printf '%s\n' '__PUBLIC__' >> authorized_keys || exit 70
    printf 'SSHELTER_ADDED\n'
fi
