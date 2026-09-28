set -u
for t in 25.1 25.7 25.7.11 26.1 26.7 master; do
  f=/w/$t.inc; cp /src/$t/interfaces.inc $f; orig=$(sha256sum < $f)
  s0=$(php /ref/hookctl.php status $f)
  php /ref/hookctl.php apply $f; a1=$?; s1=$(php /ref/hookctl.php status $f); h1=$(sha256sum < $f)
  php /ref/hookctl.php apply $f >/dev/null; a2=$?; h2=$(sha256sum < $f)
  cmp -s <(diff /src/$t/interfaces.inc $f | grep '^>' ) /dev/null && same=nodiff || same="$(diff /src/$t/interfaces.inc $f | grep -c '^>') lines added"
  php /ref/hookctl.php revert $f; r=$?; h3=$(sha256sum < $f)
  echo "$t: status0=$s0 apply=$a1 status1=$s1 [$same] reapply=$a2 idempotent=$([ "$h1" = "$h2" ] && echo yes || echo NO) revert=$r byte-identical=$([ "$orig" = "$h3" ] && echo yes || echo NO)"
done
# patched file equals the tested .diff output for 26.7
cp /src/26.7/interfaces.inc /w/x.inc; php /ref/hookctl.php apply /w/x.inc; cmp /w/x.inc /src/p/b/src/etc/inc/interfaces.inc && echo "hookctl output == os-if-pppoe-26.7.diff result: yes"
# negative: core changes the mpd5 launch line
sed "s#/usr/local/sbin/mpd5 -b -d /var/etc#/usr/local/sbin/mpd5 -b -k -d /var/etc#" /src/26.7/interfaces.inc > /w/neg1.inc; php /ref/hookctl.php apply /w/neg1.inc; echo "neg1 rc=$? unchanged=$(cmp -s /w/neg1.inc <(sed 's#mpd5 -b -d#mpd5 -b -k -d#' /src/26.7/interfaces.inc) && echo yes)"
# negative: duplicated context (anchor ambiguous)
cat /src/26.7/interfaces.inc /src/26.7/interface_ppps_reset.php > /w/neg2.inc; php /ref/hookctl.php apply /w/neg2.inc; echo "neg2 rc=$?"
# negative: user hand-edited hook line -> revert refuses rather than guess
cp /src/26.7/interfaces.inc /w/neg3.inc; php /ref/hookctl.php apply /w/neg3.inc; sed -i 's#using mpd5: #using mpd5 :#' /w/neg3.inc; php /ref/hookctl.php revert /w/neg3.inc; echo "neg3 rc=$?"
