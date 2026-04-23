
nft add set inet filter ftp_abusers '{ type ipv4_addr; flags timeout; }'


nft flush set inet filter ftp_abusers

nft add chain inet filter ftp_guard

nft flush chain inet filter ftp_guard

nft add rule inet filter input jump ftp_guard

nft add rule inet filter ftp_guard ip saddr @ftp_abusers drop

nft add rule inet filter ftp_guard ct state established,related accept

nft add rule inet filter ftp_guard \
  tcp dport 21 ct state new \
  limit rate 5/minute burst 3 packets \
  accept

nft add rule inet filter ftp_guard \
  tcp dport 21 ct state new \
  add @ftp_abusers '{ ip saddr timeout 10m }' \
  drop

nft add rule inet filter ftp_guard tcp dport 21 accept

