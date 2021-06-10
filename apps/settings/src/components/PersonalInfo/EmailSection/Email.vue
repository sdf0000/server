<!--
  - @copyright 2021 Christopher Ng <chrng8@gmail.com>
  -
  - @author 2021 Christopher Ng <chrng8@gmail.com>
  -
  - @license GNU AGPL version 3 or any later version
  -
  - This program is free software: you can redistribute it and/or modify
  - it under the terms of the GNU Affero General Public License as
  - published by the Free Software Foundation, either version 3 of the
  - License, or (at your option) any later version.
  -
  - This program is distributed in the hope that it will be useful,
  - but WITHOUT ANY WARRANTY; without even the implied warranty of
  - MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  - GNU Affero General Public License for more details.
  -
  - You should have received a copy of the GNU Affero General Public License
  - along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<template>
	<div>
		<div class="email-container">
			<input
				ref="email"
				type="email"
				:name="inputName"
				:placeholder="inputPlaceholder"
				:value="email"
				autocapitalize="none"
				autocomplete="on"
				autocorrect="off"
				required="true"
				@input="onEmailChange">

			<Actions
				class="actions-email"
				:aria-label="t('settings', 'Email options')"
				:disabled="actionsDisabled"
				:force-menu="true">
				<ActionButton
					aria-label="deleteEmailLabel"
					:close-after-click="true"
					icon="icon-delete"
					@click.stop.prevent="deleteEmail">
					{{ deleteEmailLabel }}
				</ActionButton>
			</Actions>

			<transition name="fade">
				<span v-if="showCheckmarkIcon" class="icon-checkmark" />
				<span v-else-if="showErrorIcon" class="icon-error" />
			</transition>
		</div>

		<em v-if="primary">
			{{ t('settings', 'Primary email for password reset and notifications') }}
		</em>
	</div>
</template>

<script>
import Actions from '@nextcloud/vue/dist/Components/Actions'
import ActionButton from '@nextcloud/vue/dist/Components/ActionButton'
import debounce from 'debounce'

import { savePrimaryEmail, saveAdditionalEmail, removeAdditionalEmail, updateAdditionalEmail } from '../../../service/PersonalInfoService'

export default {
	name: 'Email',

	components: {
		Actions,
		ActionButton,
	},

	props: {
		email: {
			type: String,
			required: true,
		},
		primary: {
			type: Boolean,
			default: false,
		},
		index: {
			type: Number,
			default: 0,
		},
	},

	data() {
		return {
			initialEmail: this.email,
			showCheckmarkIcon: false,
			showErrorIcon: false,
		}
	},

	computed: {
		inputName() {
			if (this.primary) {
				return 'email'
			}
			return 'additionalEmail[]'
		},

		inputPlaceholder() {
			if (this.primary) {
				return t('settings', 'Your email address')
			}
			return t('settings', 'Additional email address {index}', { index: this.index + 1 })
		},

		actionsDisabled() {
			return this.containsNoWhitespace(this.email)
		},

		deleteEmailLabel() {
			if (this.primary) {
				return t('settings', 'Erase email')
			}
			return t('settings', 'Delete email')
		},
	},

	methods: {
		onEmailChange(e) {
			this.$emit('update:email', e.target.value)
			this.debounceEmailChange()
		},

		debounceEmailChange: debounce(async function() {
			// Only run when valid AND entire email contains no whitespace OR email is empty string
			if ((this.$refs.email?.checkValidity() && this.containsNoWhitespace(this.email)) || this.email === '') {
				if (this.primary) {
					await this.updatePrimaryEmail()
				} else {
					if (this.email === '') {
						await this.deleteAdditionalEmail()
					} else if (this.initialEmail === '') {
						await this.addAdditionalEmail()
					} else {
						await this.updateAdditionalEmail()
					}
				}
			}
		}, 300),

		async deleteEmail() {
			if (this.primary) {
				this.$emit('update:email', '')
				this.$nextTick(async() => await this.updatePrimaryEmail())
			} else {
				await this.deleteAdditonalEmail()
			}
		},

		async updatePrimaryEmail() {
			try {
				const responseData = await savePrimaryEmail(this.email)
				this.showStatusIcon(responseData.ocs?.meta?.status)
			} catch (e) {
				if (this.email === '') {
					this.logger.error('Unable to delete primary email address', e)
				} else {
					this.logger.error('Unable to update primary email address', e)
				}
			}
		},

		async addAdditionalEmail() {
			try {
				const responseData = await saveAdditionalEmail(this.email)
				this.showStatusIcon(responseData.ocs?.meta?.status)
			} catch (e) {
				this.logger.error('Unable to add additional email address', e)
			}
		},

		async updateAdditionalEmail() {
			try {
				const responseData = await updateAdditionalEmail(this.initialEmail, this.email)
				this.showStatusIcon(responseData.ocs?.meta?.status)
			} catch (e) {
				this.logger.error('Unable to update additional email address', e)
			}
		},

		async deleteAdditionalEmail() {
			try {
				const responseData = await removeAdditionalEmail(this.initialEmail)
				this.handleDelete(responseData.ocs?.meta?.status)
			} catch (e) {
				this.logger.error('Unable to delete additional email address', e)
			}
		},

		containsNoWhitespace(string) {
			return /^\S+$/.test(string)
		},

		handleDelete(status) {
			if (status === 'ok') {
				this.$emit('deleteAdditionalEmail')
			} else {
				this.showStatusIcon('error')
			}
		},

		showStatusIcon(status) {
			if (status === 'ok') {
				this.showCheckmarkIcon = true
				setTimeout(() => { this.showCheckmarkIcon = false }, 2000)
			} else {
				this.showErrorIcon = true
				setTimeout(() => { this.showErrorIcon = false }, 2000)
			}
		},
	},
}
</script>

<style lang="scss" scoped>
	.email-container {
		display: grid;
		align-items: center;

		input[type=email] {
			grid-area: 1 / 1;
		}

		.actions-email {
			grid-area: 1 / 1;
			justify-self: flex-end;
			height: 30px;

			&::v-deep button {
				margin-right: 5px;
				height: 30px !important;
				min-height: 30px !important;
				width: 30px !important;
				min-width: 30px !important;

				&:disabled {
					cursor: default;
				}
			}
		}

		.icon-checkmark,
		.icon-error {
			grid-area: 1 / 1;
			justify-self: flex-end;
			margin-right: 39px;
			top: 0;
			right: 0;
			float: none;
		}
	}

	.fade-enter-active {
		transition: opacity 200ms ease-out;
	}

	.fade-leave-active {
		transition: opacity 300ms ease-out;
	}

	.fade-enter,
	.fade-leave-to {
		opacity: 0;
	}
</style>
