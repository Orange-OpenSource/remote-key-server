# Contributing to remote-key-server
First off, thanks for taking time to contribute !

The following is a set of guidelines for contributing to remote-key-server, which is hosted in the [Orange-OpenSource Organization](https://github.com/Orange-Opensource) on GitHub. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request as described in [How Can I contribute?](#how-can-i-contribute) section.

## What should I know before I get started?
First of all you should read README.md and try the Getting started section.

Remote-key-server is an https server developped in Go. 
It serves a REST API which specification is defined in [rks-openapi.yml](https://github.com/Orange-OpenSource/remote-key-server/blob/master/rks-openapi.yaml).
OpenAPI 3.0.0 standard is used.

Remote-key-server repository also provides a set of tests for each endpoint.
We took care to have corresponding test each time we added a new endpoint so consider adding tests for your modifications so that we keep a good test coverage.

The remote-key-server repository leverages Make to speed up development. All make targets are based on Docker. You can have a brief overview of the differents available targets by running `make help`

## Developping remote-key-server
If your contribution involve a change in the API (new/updated endpoint, new/updated endpoint parameter) you should start by **updating the specification** [rks-openapi.yml](https://github.com/Orange-OpenSource/remote-key-server/blob/master/rks-openapi.yaml).
Then, you should run:
```bash
$ make run-openapi-webui
```  
This will check OpenAPI syntax and open an OpenAPI web viewer in your browser at http://localhost:8088/

You can then implement your change in the **go server code**.

To compile and run the Go API server along other required remote-key-server components:
```bash
$ make dev-env
```

Then you can start to **implement and run tests**.
The tests are written in Python3 using pytest. You can draw inspiration from existings tests in [./tests/test/](./tests/test). Pay attention to pytest fixtures used for test initialization in [./tests/test/conftest.py](./tests/test/conftest.py)

First generate the remote-key-server python client needed for the tests. The client is generated using the OpenAPI specification.
```bash
$ make generate-rks-client
```

You can then implement your tests.

To run the tests on a fresh instance of the remote-key-server run:
```bash
$ make test
```
exit 0 status ensure everything is working!

The test target will spin up a new dev-env every time it is run. So when you are comfortable with the different targets, you only have to run `make test` to build the go binary, build the docker images, generate the python client, start the development environment and run the tests. However it is useful at first to understand each make target and what they do.

A simple productivity boost is to run the tests automatically when a Go or Python file has been modified. You can achieve that using the entr tool (https://github.com/eradman/entr):
```bash
$ find . -iname '*.go' -o -iname '*.py' | entr make test
```

## Focus on Makefile
The Makefile is built around docker for all the targets.
This ensures tools versions compatibility across all contributors.

We tried to take into account the fact that you could be behind an **http proxy server** in retrieving corresponding environment variable.
If you encounter an error, you probably need to hard set these variables at the beginning of Makefile.

If you focus on "test" Make target, which is the most complete target, you will see that it builds and runs 5 docker containers:
- **rks-consul** which is used as storage backend by vault server
- **rks-vault** which is the HashiCorp vault server on which remote-key-server relies to secure and store its data
- **rks-server** which is our Go REST API
- **rks-mock-callback-server** which is a mock of a Group Manager. It mocks oAuth and callback-url called by rks-server when a node registers (to check if node is authorized)
- **rks-test** which runs the python tests on the rks-server.

They all share a docker bridge network named "rks".

Note: rks-vault is exposed on localhost:8200. You can login to its Web UI with root token which is stored (generated each time make test is launch) in the same directory than Makefile: 
```bash
$ cat root_token
s.AFYEBp0Vr9qsU3YZGV52LMrl
```

## Coding Conventions
Standard Gofmt for go coding
Black for Python

We lint with golangci-lint.

## How Can I Contribute?
For any contribution, such as suggesting enhancement, reporting bugs, please fill an Issue.

Issue title has to be relatively short, additionnal and clear information can be written in description field.
Additionnally, feel free to use label for your issue.

Once issue has been created, we ask to create a branch to work on.
Please ensure "make test" return exit code 0 before committing into the branch.

When this is done, make a pull request and assign it to **gfeun** or **celinenicolas22** or both.
Please refers pull request to issue. 

