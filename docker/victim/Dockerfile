FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    apache2 \
    rsyslog \
    net-tools \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install flask --quiet

# Test foydalanuvchilar (brute force demo uchun)
RUN useradd -m -s /bin/bash testuser && echo 'testuser:SecurePass123!' | chpasswd
RUN useradd -m -s /bin/bash admin    && echo 'admin:Admin@2024'        | chpasswd
RUN echo 'root:RootPass!123' | chpasswd

# SSH: parol bilan kirish ruxsati
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/'   /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/'  /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/'                 /etc/ssh/sshd_config

# rsyslog: auth loglarni shared volume ga yozish
RUN mkdir -p /victim-logs
COPY rsyslog-victim.conf /etc/rsyslog.d/10-victim.conf

COPY log_api.py    /log_api.py
COPY entrypoint.sh /entrypoint.sh
RUN  chmod +x /entrypoint.sh

EXPOSE 22 80 5000
CMD ["/entrypoint.sh"]
