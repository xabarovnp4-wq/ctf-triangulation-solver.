FROM gitpod/workspace-python-3.11

USER gitpod

RUN sudo apt-get update && \
    sudo apt-get install -y python3-pip && \
    sudo rm -rf /var/lib/apt/lists/*
