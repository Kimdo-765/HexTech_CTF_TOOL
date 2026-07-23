FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        binutils \
        sleuthkit \
        qemu-utils \
        ewf-tools libewf-dev \
        file unzip \
        ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
        volatility3==2.28.0 \
        yara-python \
 && python3 -c "import volatility3; print('volatility3', volatility3.__version__ if hasattr(volatility3,'__version__') else 'ok')"

COPY forensic/*.py /opt/forensic/

WORKDIR /job
ENTRYPOINT ["python3", "/opt/forensic/collect.py"]
