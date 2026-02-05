.PHONY: up down logs demo

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker logs --tail 200 kasbah-core-api-1 || true

demo: up
	BASE=http://localhost:8002 ./demo/demo.sh
