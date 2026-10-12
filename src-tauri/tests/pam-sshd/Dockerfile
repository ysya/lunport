# check=skip=SecretsUsedInArgOrEnv
# A real OpenSSH server with PAM, for the password and keyboard-interactive tests of the SSH engine (own-ssh spec §12). A scratch sshd
# started by a test cannot check passwords (no PAM without root), so those logins are tested against this.
#
#   docker build --build-arg TEST_PASSWORD='choose-something' -t sshelter-pam-sshd src-tauri/tests/pam-sshd
#   docker run -d --name sshelter-pam-sshd -p 127.0.0.1:2222:22 sshelter-pam-sshd
#   SSHELTER_PAM_PORT=2222 SSHELTER_PAM_USER=sshelter SSHELTER_PAM_PASSWORD='choose-something' \
#     cargo test --locked --lib -- ssh::engine_tests::login_methods::pam        (from src-tauri/)
#   docker rm -f sshelter-pam-sshd
#
# Throwaway: the user's password is whatever you pass at build time (so the BuildKit check about secrets in ARG is switched off above),
# the port is published on localhost only, and the image is not meant for anything else.
FROM ubuntu:24.04
ARG TEST_USER=sshelter
ARG TEST_PASSWORD
RUN test -n "$TEST_PASSWORD" || { echo "pass --build-arg TEST_PASSWORD=<a password for the test user>" >&2; exit 1; }
# Docker's default capabilities do not let pam_loginuid write /proc/self/loginuid; as `required` it ends every session right after the
# login, so it is made optional.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd --create-home --shell /bin/bash "$TEST_USER" \
 && echo "$TEST_USER:$TEST_PASSWORD" | chpasswd \
 && sed -i 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@' /etc/pam.d/sshd \
 && grep -q 'session optional pam_loginuid.so' /etc/pam.d/sshd
COPY sshd_config.test /etc/ssh/sshd_config.d/00-sshelter-test.conf
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
