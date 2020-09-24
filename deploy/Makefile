ANSIBLE_SSH_USER := <TARGET_HOST_USER>

.PHONY: rks_install

roles/ansible-consul:
	git clone https://github.com/brianshumate/ansible-consul roles/ansible-consul
	cd roles/ansible-consul/ && git checkout v2.5.4

roles/ansible-vault:
	git clone https://github.com/brianshumate/ansible-vault roles/ansible-vault
	cp ./vault_systemd_unconfined.service.j2 ./roles/ansible-vault/templates/
	cd roles/ansible-vault/ && git checkout v2.5.2
build_rks:
	cd ../ && export CGO_ENABLED=0 && go mod download && go build -o deploy/roles/ansible-rks-server/files/rks-server ./cmd/remote-key-server/
	 
rks_install: build_rks roles/ansible-consul roles/ansible-vault
	ANSIBLE_HOST_KEY_CHECKING=false ansible-playbook -v -i ./hosts --user=${ANSIBLE_SSH_USER} --become ./rks_install.yaml

