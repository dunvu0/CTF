FROM python:3.8-slim

WORKDIR /app

COPY . .

RUN pip3 install -r requirements.txt
# RUN pip install debugpy
# EXPOSE 5000

CMD ["python3", "main.py"]
# CMD ["python3", "-m" , "debugpy", "--listen", "0.0.0.0:5678", "main.py"]