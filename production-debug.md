# Production Server Debug Commands

Production server'da aşağıdaki komutları çalıştırın:

## 1. Container Status
```bash
docker ps --filter "name=aun-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

## 2. X509 Service Logs
```bash
docker logs aun-x509-service --tail 20
```

## 3. Container İçindeki Process
```bash
docker exec aun-x509-service cat /proc/net/tcp
```

## 4. Environment Variables
```bash
docker exec aun-x509-service env | grep -E "(AUNSORM|PORT)"
```

## 5. Service Binary Check
```bash
docker exec aun-x509-service ls -la /usr/local/bin/
```

## 6. Port Listen Check
```bash
# Production server'da (host'ta)
netstat -tulpn | grep 50013
ss -tulpn | grep 50013
```

## 7. Container Network
```bash
docker network ls
docker network inspect aunsorm-network
```

## 8. Compose Status
```bash
docker compose ps
```

Bu komutların çıktılarını paylaşın, sorunu teşhis edelim.