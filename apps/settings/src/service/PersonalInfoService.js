/**
 * @copyright 2021, Christopher Ng <chrng8@gmail.com>
 *
 * @author Christopher Ng <chrng8@gmail.com>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

import axios from '@nextcloud/axios'
import { getCurrentUser } from '@nextcloud/auth'
import { generateOcsUrl } from '@nextcloud/router'
import confirmPassword from '@nextcloud/password-confirmation'

// TODO provide constants through @nextcloud/capabilities

/** Enum of account properties */
const ACCOUNT_PROPERTY_ENUM = Object.freeze({
	PROPERTY_AVATAR: 'avatar',
	PROPERTY_DISPLAYNAME: 'displayname',
	PROPERTY_PHONE: 'phone',
	PROPERTY_EMAIL: 'email',
	PROPERTY_WEBSITE: 'website',
	PROPERTY_ADDRESS: 'address',
	PROPERTY_TWITTER: 'twitter',
	COLLECTION_EMAIL: 'additional_mail',
})

/** Scope suffix constant */
const SCOPE_SUFFIX = 'Scope'

/** Object of federation scopes */
export const FEDERATION_SCOPES = Object.freeze({
	'v2-private': {
		name: 'v2-private',
		displayName: t('settings', 'Private'),
		tooltip: t('settings', 'Only visible to people matched via phone number integration through Talk on mobile'),
		iconClass: 'icon-phone',
	},
	'v2-local': {
		name: 'v2-local',
		displayName: t('settings', 'Local'),
		tooltip: t('settings', 'Only visible to people on this instance and guests'),
		iconClass: 'icon-password',
	},
	'v2-federated': {
		name: 'v2-federated',
		displayName: t('settings', 'Federated'),
		tooltip: t('settings', 'Only synchronize to trusted servers'),
		iconClass: 'icon-contacts-dark',
	},
	'v2-published': {
		name: 'v2-published',
		displayName: t('settings', 'Published'),
		tooltip: t('settings', 'Synchronize to trusted servers and the global and public address book'),
		iconClass: 'icon-link',
	},
})

/**
 * Save the primary email of the user
 *
 * @param {string} email the primary email
 * @returns {Object}
 */
export const savePrimaryEmail = async(email) => {
	const userId = getCurrentUser().uid
	// TODO upgrade @nextcloud/router to v2.0 so we can remove the .slice() trailing slash hacks (same below)
	const url = generateOcsUrl(`cloud/users/${userId}`, 2).slice(0, -1)

	await confirmPassword()

	const res = await axios.put(url, {
		key: ACCOUNT_PROPERTY_ENUM.PROPERTY_EMAIL,
		value: email,
	})

	return res.data
}

/**
 * Save a new additional email for the user
 *
 * @param {string} email the new additional email
 * @returns {Object}
 */
export const saveAdditionalEmail = async(email) => {
	const userId = getCurrentUser().uid
	const url = generateOcsUrl(`cloud/users/${userId}`, 2).slice(0, -1)

	await confirmPassword()

	const res = await axios.put(url, {
		key: ACCOUNT_PROPERTY_ENUM.COLLECTION_EMAIL,
		value: email,
	})

	return res.data
}

/**
 * Remove the additional email of the user
 *
 * @param {string} email the additional email
 * @returns {Object}
 */
export const removeAdditionalEmail = async(email) => {
	const userId = getCurrentUser().uid
	const url = generateOcsUrl(`cloud/users/${userId}/${ACCOUNT_PROPERTY_ENUM.COLLECTION_EMAIL}`, 2).slice(0, -1)

	await confirmPassword()

	const res = await axios.put(url, {
		key: email,
		value: '',
	})

	return res.data
}

/**
 * Update the additional email of the user
 *
 * @param {string} prevEmail the additional email to be updated
 * @param {string} newEmail the new additional email
 * @returns {Object}
 */
export const updateAdditionalEmail = async(prevEmail, newEmail) => {
	const userId = getCurrentUser().uid
	const url = generateOcsUrl(`cloud/users/${userId}/${ACCOUNT_PROPERTY_ENUM.COLLECTION_EMAIL}`, 2).slice(0, -1)

	await confirmPassword()

	const res = await axios.put(url, {
		key: prevEmail,
		value: newEmail,
	})

	return res.data
}

/**
 * Save the federation scope for the primary email of the user
 *
 * @param {string} scope the federation scope
 * @returns {Object}
 */
export const saveScope = async(scope) => {
	const userId = getCurrentUser().uid
	const url = generateOcsUrl(`cloud/users/${userId}`, 2).slice(0, -1)

	await confirmPassword()

	const res = await axios.put(url, {
		key: `${ACCOUNT_PROPERTY_ENUM.PROPERTY_EMAIL}${SCOPE_SUFFIX}`,
		value: scope,
	})

	return res.data
}

/**
 * Save the federation scope for the additional email of the user
 *
 * @param {string} email the additional email
 * @param {string} scope the federation scope
 * @returns {Object}
 */
export const saveAdditionalEmailScope = async(email, scope) => {
	const userId = getCurrentUser().uid
	const url = generateOcsUrl(`cloud/users/${userId}/${ACCOUNT_PROPERTY_ENUM.COLLECTION_EMAIL}${SCOPE_SUFFIX}`, 2).slice(0, -1)

	await confirmPassword()

	const res = await axios.put(url, {
		key: email,
		value: scope,
	})

	return res.data
}
