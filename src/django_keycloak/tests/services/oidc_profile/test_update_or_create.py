import mock

from datetime import datetime

from dateutil.relativedelta import relativedelta
from django.test import TestCase
from freezegun import freeze_time
from keycloak.openid_connect import KeycloakOpenidConnect

from django_keycloak.factories import ClientFactory
from django_keycloak.models import RemoteUserOpenIdConnectProfile
from django_keycloak.remote_user import KeycloakRemoteUser
from django_keycloak.tests.mixins import MockTestCaseMixin

import django_keycloak.services.oidc_profile


class ServicesKeycloakOpenIDProfileUpdateOrCreateTestCase(MockTestCaseMixin,
                                                          TestCase):

    def setUp(self):
        self.client = ClientFactory(
            realm___certs='{}',
            realm___well_known_oidc='{"issuer": "https://issuer", "userinfo_endpoint": "http://userinfo_endpoint"}'
        )
        self.client.openid_api_client = mock.MagicMock(
            spec_set=KeycloakOpenidConnect)
        self.client.openid_api_client.authorization_code.return_value = {
            'id_token': 'id-token',
            'expires_in': 600,
            'refresh_expires_in': 3600,
            'access_token': 'access-token',
            'refresh_token': 'refresh-token'
        }
        self.client.openid_api_client.well_known = {
            'id_token_signing_alg_values_supported': ['signing-alg']
        }
        self.client.openid_api_client.decode_token.return_value = {
            'sub': 'some-sub',
            'email': 'test@example.com',
            'given_name': 'Some given name',
            'family_name': 'Some family name'
        }

    @freeze_time('2018-03-01 00:00:00')
    @mock.patch('django_keycloak.services.oidc_profile.get_remote_user_from_profile')
    def test_create(self, get_remote_user_from_profile):
        get_remote_user_from_profile.return_value = KeycloakRemoteUser({
            'sub': 'some-sub',
            'given_name': 'Some given name',
            'family_name': 'Some family name',
        })
        django_keycloak.services.oidc_profile.update_or_create_from_code(
            client=self.client,
            code='some-code',
            redirect_uri='https://redirect'
        )
        self.client.openid_api_client.authorization_code\
            .assert_called_once_with(code='some-code',
                                     redirect_uri='https://redirect')
        self.client.openid_api_client.decode_token.assert_called_once_with(
            token='id-token',
            key=dict(),
            algorithms=['signing-alg'],
            issuer='https://issuer'
        )

        profile = RemoteUserOpenIdConnectProfile.objects.get(sub='some-sub')
        self.assertEqual(profile.sub, 'some-sub'),
        self.assertEqual(profile.access_token, 'access-token')
        self.assertEqual(profile.refresh_token, 'refresh-token')
        self.assertEqual(profile.expires_before, datetime(
            year=2018, month=3, day=1, hour=0, minute=10, second=0
        ))
        self.assertEqual(profile.refresh_expires_before, datetime(
            year=2018, month=3, day=1, hour=1, minute=0, second=0
        ))

        user = profile.user
        self.assertEqual(user.username, 'some-sub')
        self.assertEqual(user.first_name, 'Some given name')
        self.assertEqual(user.last_name, 'Some family name')

    @freeze_time('2018-03-01 00:00:00')
    @mock.patch('django_keycloak.services.oidc_profile.get_remote_user_from_profile')
    def test_update(self, get_remote_user_from_profile):
        # user = KeycloakRemoteUser({'sub': 'admin'})
        get_remote_user_from_profile.return_value = KeycloakRemoteUser({
            'sub': 'some-sub',
            'given_name': 'Some given name',
            'family_name': 'Some family name',
        })
        profile = RemoteUserOpenIdConnectProfile.objects.create(
            realm=self.client.realm,
            sub='some-sub',
            access_token='access-token',
            expires_before=datetime.now() + relativedelta(minutes=10),
            refresh_token='refresh-token',
            refresh_expires_before=datetime.now() + relativedelta(hours=1)
        )
        # profile.user = user

        django_keycloak.services.oidc_profile.update_or_create_from_code(
            client=self.client,
            code='some-code',
            redirect_uri='https://redirect'
        )
        self.client.openid_api_client.authorization_code\
            .assert_called_once_with(code='some-code',
                                     redirect_uri='https://redirect')
        self.client.openid_api_client.decode_token.assert_called_once_with(
            token='id-token',
            key=dict(),
            algorithms=['signing-alg'],
            issuer='https://issuer'
        )

        # profile.refresh_from_db()
        self.assertEqual(profile.sub, 'some-sub')
        self.assertEqual(profile.access_token, 'access-token')
        self.assertEqual(profile.refresh_token, 'refresh-token')
        self.assertEqual(profile.expires_before, datetime(
            year=2018, month=3, day=1, hour=0, minute=10, second=0
        ))
        self.assertEqual(profile.refresh_expires_before, datetime(
            year=2018, month=3, day=1, hour=1, minute=0, second=0
        ))

        user = profile.user
        # user.refresh_from_db()
        self.assertEqual(user.username, 'some-sub')
        self.assertEqual(user.first_name, 'Some given name')
        self.assertEqual(user.last_name, 'Some family name')
