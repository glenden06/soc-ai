.PHONY: help demo up down logs test lint clean

help:
	@echo "make demo   - copie les logs d'exemple puis lance la stack complete"
	@echo "make up     - docker compose up --build -d"
	@echo "make down   - arrete la stack et supprime le volume de donnees"
	@echo "make logs   - suit les journaux des conteneurs"
	@echo "make test   - lance la suite de tests"
	@echo "make lint   - lance ruff sur le code Python"

demo:
	cp samples/* logs/ 2>/dev/null || true
	docker compose up --build -d
	@echo "Dashboard : http://localhost:3000 - API : http://localhost:8000/docs"

up:
	docker compose up --build -d

down:
	docker compose down -v

logs:
	docker compose logs -f

test:
	python -m pytest tests/ -v

lint:
	ruff check .

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ dashboard/node_modules dashboard/dist
