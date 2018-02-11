echo "id,dns" > ip_dns.csv
cut -d, -f4,6 id_search.csv | awk -F, '{print $2 "," $1}'  | grep -v ",$" | grep -v "^," | sort | uniq >> ip_dns.csv
cut -d, -f5,6 mood.csv | awk -F, '{print $2 "," $1}'  | grep -v ",$" | grep -v "^," | sort | uniq >> ip_dns.csv
./dns_resolve id_search.csv ip_dns.csv 5 3
./dns_resolve mood.csv ip_dns.csv 4 5
