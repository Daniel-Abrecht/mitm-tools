#!/bin/bash

set -ex

exec 99<&0 0</dev/null

cd "$(dirname "$(realpath "$0")")/intercepted/http/"

quote(){
  local quoted=${1//\'/\'\\\'\'};
  printf "'%s'" "$quoted"
}

dest=":$(sed "s|/|∕|g" <<<"$1$2")"

exec 9>".lock$dest"
flock 9 || exit 1

if [ -s "f$dest" ]
  then exit 0
fi

if [ -n "$start" ]
then
  [ -d "d$dest" ] || mkdir "d$dest"
  cd "d$dest"
  smaller=
  bigger=
  for p in $(printf "%s\n" *.part | grep -o '^[0-9]*' | sort -n)
  do
    [ -n "$p" ] || continue
    if [ "$p" -gt "$start" ]
    then
      bigger="$p"
      break
    fi
    smaller="$p"
  done
  f="$start"
  if [ -n "$smaller" ] && [ "$(bc <<<"$(wc -c "$smaller.part" | grep -o '^[0-9]*') + $smaller")" -le "$start" ]
    then f="$smaller"
  fi
  seek="$(bc <<<"$f - $start")"
  if [ -n "$bigger" ] && [ "$bigger" -lt "$end" ]
    then end="$bigger"
  fi
  if [ "$start" -lt "$end" ]
  then
    echo "Saving content part $start:$end offset $seek at: $(quote "d$dest")/$f.part"
    count="$(bc <<<"$end - $start")"
    dd bs=4096 seek="$seek" of="$f.part" count="$count"  iflag=skip_bytes,count_bytes oflag=seek_bytes <&99
  fi
  if [ "$end" = "$bigger" ]
  then
    echo "Appending $bigger.part to $f.part"
    cat <"$bigger.part" >>"$f.part"
  fi
  if [ "$full" != '*' ] && [ "$f" == 0 ] && [ "$(wc -c 0.part | grep -o '^[0-9]*')" -ge "$full" ]
  then
    echo "File complete: $(quote "$dest")"
    mv "0.part" "../f$dest"
    cd ..
    rmdir "d$dest"
  fi
else
  echo "Saving content at: $(quote "f$dest")"
  dd bs=4096 >"f$dest" <&99
fi
