FROM python:3
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache -r requirements.txt
RUN python -m spacy download en_core_web_sm
COPY . .
CMD ["python","app.py"]
