# IAM Behavioral Tests

This folder contains tests that aim to test and codify the behavior of IAM policy decisions (Allow or Deny) in very specific cases. This information allows us to:

1. Ensure that IAM does not change their underlying implementation without us knowing about it (via the failure of these tests)
2. Provide up to date documentation about our expectations of how IAM behaves, to ensure we are accurately replicating the same behavior in our policy analysis logic.


## Running

The tests utilize two sets of AWS credentials, `super` credentials which take care of IAM role creation and test case setup, and `role` credentials which is a short-lived role configured with a small policy that will attempt to do an action.
To get started, you will need to have a "superuser" credential configured in one of the ways described in the [AWS Quickstart Docs](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html). This is typically your own user
in the Divvy QA instance with a broad set of permissions.

To run the actual tests, execute:

```
pytest --capture=no tests/iam
```

If you would like to execute the tests in parallel, run:

```
pytest -n 4 --capture=no tests/iam
```
