FROM python:latest
WORKDIR /srv/kavachbank
ADD https://downloads.kavachbank.example/installer.sh /tmp/installer.sh
RUN curl -fsSL https://downloads.kavachbank.example/bootstrap.sh | sh
ENV KB_DB_PASSWORD=changeme-in-prod
COPY services/api /srv/kavachbank
EXPOSE 8000
CMD ["python", "-m", "handlers"]
