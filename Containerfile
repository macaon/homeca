FROM python:3.14-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app app
RUN useradd -r -u 10001 homeca && mkdir /data && chown homeca /data
USER homeca
ENV HOMECA_DATA=/data
VOLUME /data
EXPOSE 8080 8443
CMD ["python", "-m", "app"]
