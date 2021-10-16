#!/bin/bash

OLDIFS="$IFS"

set -e

exec 99<&0 0</dev/null

cd "$(dirname "$(realpath "$0")")/intercepted/http/"

quote(){
  local quoted=${1//\'/\'\\\'\'};
  printf "'%s'" "$quoted"
}

domain="$1"; shift
location="$1"; shift

url2local(){
  local url="$1"
  local d=
  local l=
  local rpath=
  printf '%s:' "$2"
  if grep -q '^[a-zA-Z0-9+-]*://' <<<"$url"
    then rpath="$(sed 's|^[a-zA-Z0-9+-]*://||' <<<"$url")"
  elif [ "${url[0]}" = / ]
    then rpath="$domain$url"
    else rpath="$domain$(dirname "$(grep -o '^[^?]*' <<<"$location")XXX" | grep -v '^\.$')/$url"
  fi
  IFS='/'
  read d l <<<"$rpath"
  IFS="$OLDIFS"
  echo "$d-$(sha256sum <<<"$l" | grep -o '^[^ ]*')"
}

url="https://$domain$location"
dest="$(url2local "$url")"

exec 9>".lock$dest"
flock 9 || exit 1

suattr(){
  setfattr -n "user.xdg.origin.url" -v "$url" "$1"
}

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
        suattr "$prev.part"
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
  timeout 90 dd bs=4096 seek="$seek" of="$f.part" count="$count" iflag=skip_bytes,count_bytes oflag=seek_bytes conv=notrunc <&99
  suattr "$f.part"
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

if [ -f "f$dest" ]
  then suattr "f$dest"
fi

recombine_extm3u(){

  sequence="$(grep '#EXT-X-MEDIA-SEQUENCE:' <"f$dest" | head -n 1 | grep -o '[0-9]*' | head -c 1)"
  IFS=$'\n'
  newlines=( $(grep -v '^[#]\|^$\|^\s*$' <"f$dest") )
  IFS="$OLDIFS"
  oldlines=()

  if [ -f "m3u$dest.m3u8" ]
  then
    IFS=$'\n'
    oldsequence="$(grep '#EXT-X-MEDIA-SEQUENCE:' <"m3u$dest.m3u8" | head -n 1 | grep -o '[0-9]*' | head -c 1)"
    IFS="$OLDIFS"
    if [ -n "$oldsequence" ] && [ -n "$sequence" ]
      then oldlines=( $(grep -v '^[#]\|^$\|^\s*$' <"m3u$dest.m3u8") )
      else oldsequence="$sequence"
    fi
  fi

  if [ -z "$oldsequence" ] || [ -z "$sequence" ]
  then
    (
      echo "#EXTM3U"
      if [ -n "$sequence" ]
        then echo "#EXT-X-MEDIA-SEQUENCE: $sequence"
      fi
      for entry in "${newlines[@]}"
        do url2local "$entry" f
      done
    ) >"m3u$dest.m3u8"
    return
  fi

  sequence_min="$sequence"
  if [ "$sequence_min" -le "$oldsequence" ]
    then sequence_min="$oldsequence"
  fi

  nseq_end="$(bc <<<"$sequence + ${#newlines[@]}")"
  oseq_end="$(bc <<<"$oldsequence + ${#oldlines[@]}")"
  sequence_max="$nseq_end"
  if [ "$sequence_max" -le "$oseq_end" ]
    then sequence_max="$oseq_end"
  fi

  # Sequences probably unrelated
  if [ "$(bc <<<"$sequence_max - $sequence_min")" -gt 100000 ]
  then
    (
      echo "#EXTM3U"
      if [ -n "$sequence" ]
        then echo "#EXT-X-MEDIA-SEQUENCE: $sequence"
      fi
      for entry in "${newlines[@]}"
        do url2local "$entry" f
      done
    ) >"m3u$dest.m3u8"
    return
  fi

  (
    echo "#EXTM3U"
    echo "#EXT-X-MEDIA-SEQUENCE: $sequence_min"
    i="$sequence_min"
    while [ "$i" -lt "$sequence_max" ]
    do
      if [ "$i" -ge "$sequence" ] && [ "$i" -lt "$nseq_end" ]
        then url2local "${newlines[$i-$sequence]}" f
      elif [ "$i" -ge "$oldsequence" ] && [ "$i" -lt "$oseq_end" ]
        then url2local "${oldlines[$i-$oldsequence]}" f
        else echo ?
      fi
      i="$(expr "$i" + 1)"
    done
  ) >"m3u$dest.m3u8"
}

set +e

if [ -f "f$dest" ]
then
  read -n 20 header <"f$dest"
  if [ "$header" = "#EXTM3U" ]
    then recombine_extm3u
  fi
fi

if [ -f "m3u$dest.m3u8" ]
  then suattr "m3u$dest.m3u8"
fi
