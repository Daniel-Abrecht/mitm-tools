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

echo "$start $end $full $dest"

merge_all(){
  prev=
  for next in $(printf "%s\n" *.part | grep -o '^[0-9]*' | sort -n)
  do
    [ -n "$next" ] || continue
    if [ -n "$prev" ]
    then
      pend="$(bc <<<"$prev + $(wc -c "$prev.part" | grep -o '^[0-9]*')")"
      nend="$(bc <<<"$next + $(wc -c "$next.part" | grep -o '^[0-9]*')")"
      if [ "$nend" -le "$pend" ]
        then rm "$next.part"
      elif [ "$next" -le "$pend" ]
      then
        seek="$(bc <<<"$pend - $prev")"
        skip="$(bc <<<"$pend - $next")"
        echo "Merging part $next-$nend offset $skip to $prev-$pend offset $seek"
        dd bs=4096 seek="$seek" skip="$skip" if="$next.part" of="$prev.part" iflag=skip_bytes oflag=seek_bytes conv=notrunc
        rm "$next.part"
      fi
    fi
    prev="$next"
  done
}

save_partial(){
  local start="$1"; shift
  local end="$1"; shift
  local full="$1"; shift
(
  [ -d "d$dest" ] || mkdir "d$dest"
  cd "d$dest"
  smaller=
  for p in $(printf "%s\n" *.part | grep -o '^[0-9]*' | sort -n)
  do
    [ -n "$p" ] || continue
    [ "$p" -le "$start" ] || break
    smaller="$p"
  done
  f="$start"
  if [ -n "$smaller" ] && [ "$start" -le "$(bc <<<"$(wc -c "$smaller.part" | grep -o '^[0-9]*') + $smaller")" ]
    then f="$smaller"
  fi
  seek="$(bc <<<"$start - $f")"
  echo "Saving part $start-$end offset $seek at: $(quote "d$dest")/$f.part"
  count="$(bc <<<"$end - $start")"
  dd bs=4096 seek="$seek" of="$f.part" count="$count" iflag=skip_bytes,count_bytes oflag=seek_bytes conv=notrunc <&99
  if [ "$f" = 0 ]
    then ln -f "0.part" "../f$dest"
  fi
  merge_all
  if [ "$full" != '*' ] && [ "$f" = 0 ] && [ "$(wc -c 0.part | grep -o '^[0-9]*')" -ge "$full" ]
  then
    echo "File complete: $(quote "$dest")"
    ln -f "0.part" "../f$dest"
    rm *
    cd ..
    rmdir "d$dest"
  fi
);}

if [ -n "$start" ]
then
  if [ -s "f$dest" ]
  then
    flen="$(wc -c "f$dest" | grep -o '^[0-9]*')"
    if [ "$full" != "*" ] && [ "$full" -le "$flen" ]
      then exit 0
    fi
    if [ ! -f "d$dest/0.part" ]
    then
      [ -d "d$dest" ] || mkdir "d$dest"
      ln "f$dest" "d$dest/0.part"
    fi
    if [ "$(wc -c "d$dest/0.part" | grep -o '^[0-9]*')" -lt "$flen" ]
    then if ! [ "d$dest/0.part" -ef "f$dest" ]
      then save_partial 0 "$flen" "$full" 99<"f$dest"
    fi; fi
  fi
  save_partial "$start" "$end" "$full"
else
  echo "Saving content at: $(quote "f$dest")"
  dd bs=4096 of="f$dest" conv=notrunc <&99
fi
