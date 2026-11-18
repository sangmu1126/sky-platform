FROM public.ecr.aws/docker/library/python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
COPY wheels /wheels
COPY requirements.txt /requirements.txt
RUN python -m pip install --no-index --find-links=/wheels --require-hashes -r /requirements.txt && rm -rf /wheels
WORKDIR /app
COPY server.py /app/server.py
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8443
ENTRYPOINT ["python", "/app/server.py"]
