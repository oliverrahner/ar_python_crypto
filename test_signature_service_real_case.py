import signature_service
from urllib.parse import unquote
import base64
import unittest
from cryptography.exceptions import InvalidSignature


# raw redirect url from ar QA:
# https://io.rahner.me/rest/onboard?
#   state=12345&
#   token=eyJhY2NvdW50IjoiODc0ODdiMzctZGI1MS00NzJkLWI2ZTgtYjk0Y2FlNzc1ODhmIiwicmVnY29kZSI6IjYwNjk1NzE3MmQiLCJleHBpcmVzIjoiMjAyMS0wMi0wNlQxNzo1NzoyMS43NzhaIn0%3D&
#   signature=PKDQCJDiUJudtqH9jxbudimaEitnSvVf5vqecy6dhiROM%2B5sS%2FNU5vyRfhTr%2FD3Sd4f%2FD05EAzxYptFAzzVo0h4MtbiC%2F8Evf3%2FYAebvMf5nNWCK%2BUsnr5xO8KX%2BDn0xzEA6gww1PGkrOJnzWjwg3MjeGliStpPFrZlzR4t6RfJHcrBv%2Fvbsa7q59rpJ5AsKoCEgm%2FZ3cUbHijqqd%2FuFRIy%2BA8MNjXYXeHg8wW5SNKbAk12QKwTY1npuKF%2F0PedQIiTsBVPujv1RZ7hEPKsjJRRUmQ1TQd6LfYYlHgJNzhv%2B24IEIJ11e%2Fv%2BFGVvIn5VogJsFTbMsh1jOnmmCAXoJA%3D%3D

PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8xF9661acn+iS+QS+9Y\n"
    "3HvTfUVcismzbuvxHgHA7YeoOUFxyj3lkaTnXm7hzQe4wDEDgwpJSGAzxIIYSUXe\n"
    "8EsWLorg5O0tRexx5SP3+kj1i83DATBJCXP7k+bAF4u2FVJphC1m2BfLxelGLjzx\n"
    "VAS/v6+EwvYaT1AI9FFqW/a2o92IsVPOh9oM9eds3lBOAbH/8XrmVIeHofw+XbTH\n"
    "1/7MLD6IE2+HbEeY0F96nioXArdQWXcjUQsTch+p0p9eqh23Ak4ef5oGcZhNd4yp\n"
    "Y8M6ppvIMiXkgWSPJevCJjhxRJRmndY+ajYGx7CLePx7wNvxXWtkng3yh+7WiZ/Y\n"
    "qwIDAQAB\n"
    "-----END PUBLIC KEY-----"
)

SIGNATURE_FROM_REDIRECT = (
    "PKDQCJDiUJudtqH9jxbudimaEitnSvVf5vqecy6dhiROM%2B5sS%2FNU5vyRfhTr%2F"
    "D3Sd4f%2FD05EAzxYptFAzzVo0h4MtbiC%2F8Evf3%2FYAebvMf5nNWCK%2BUsnr5xO"
    "8KX%2BDn0xzEA6gww1PGkrOJnzWjwg3MjeGliStpPFrZlzR4t6RfJHcrBv%2Fvbsa7q"
    "59rpJ5AsKoCEgm%2FZ3cUbHijqqd%2FuFRIy%2BA8MNjXYXeHg8wW5SNKbAk12QKwTY"
    "1npuKF%2F0PedQIiTsBVPujv1RZ7hEPKsjJRRUmQ1TQd6LfYYlHgJNzhv%2B24IEIJ1"
    "1e%2Fv%2BFGVvIn5VogJsFTbMsh1jOnmmCAXoJA%3D%3D"
)

DATA = ("12345eyJhY2NvdW50IjoiODc0ODdiMzctZGI1MS00NzJkLWI2ZTgtYjk0Y2FlNzc1ODhmIiwicmVnY29kZSI6IjYwNjk1NzE3MmQiLCJleHBpcmVzIjoiMjAyMS0wMi0wNlQxNzo1NzoyMS43NzhaIn0=")


class TestSignatureServiceRealCase(unittest.TestCase):

    def test_verify(self):
        signature_unquoted = unquote(SIGNATURE_FROM_REDIRECT)
        signature_b64bytes = signature_unquoted.encode('utf-8')
        signature = base64.b64decode(signature_b64bytes)
        raised = False
        try:
            signature_service.verify_signature(DATA, signature, PUBLIC_KEY)
        except InvalidSignature:
            raised = True
        self.assertFalse(raised, 'Exception has been raised!')


if __name__ == '__main__':
    unittest.main()
