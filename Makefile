.PHONY: install run test docker-build docker-run clean

install:
	pip install -r requirements.txt

run:
	python inferences.py

test:
	pytest test_service.py -v

client:
	python client.py

docker-build:
	docker build -t waf-ml-service .

docker-run:
	docker run -d -p 8000:8000 --name waf-ml waf-ml-service

docker-stop:
	docker stop waf-ml && docker rm waf-ml

docker-logs:
	docker logs waf-ml

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete