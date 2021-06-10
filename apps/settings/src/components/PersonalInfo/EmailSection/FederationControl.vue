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
	<Actions
		class="actions-federation"
		:default-icon="scopeIcon"
		:aria-label="t('settings', 'Change privacy level of email')">
		<ActionButton v-for="federationScope in federationScopes"
			:key="federationScope.name"
			class="forced-action"
			:class="{ 'forced-active': scope === federationScope.name }"
			:aria-label="federationScope.tooltip"
			:close-after-click="true"
			:icon="federationScope.iconClass"
			:title="federationScope.displayName"
			@click.stop.prevent="changeScope(federationScope.name)">
			{{ federationScope.tooltip }}
		</ActionButton>
	</Actions>
</template>

<script>
import { Actions, ActionButton } from '@nextcloud/vue'

import { FEDERATION_SCOPES, saveScope } from '../../../service/PersonalInfoService'

// TODO currently hardcoded for email, should abstract this for other sections
const excludedScopes = ['v2-private']

export default {
	name: 'FederationControl',

	components: {
		Actions,
		ActionButton,
	},

	props: {
		scope: {
			type: String,
			required: true,
		},
	},

	data() {
		return {
			federationScopes: Object.values(FEDERATION_SCOPES).filter(({ name }) => !excludedScopes.includes(name)),
		}
	},

	computed: {
		scopeIcon() {
			return FEDERATION_SCOPES[this.scope].iconClass
		},
	},

	methods: {
		async changeScope(scope) {
			const prevScope = this.scope
			this.$emit('update:scope', scope)

			this.$nextTick(async() => {
				try {
					const responseData = await saveScope(this.scope)
					if (responseData.ocs?.meta?.status !== 'ok') {
						this.$emit('update:scope', prevScope)
					}
				} catch (e) {
					this.$emit('update:scope', prevScope)
					this.logger.error('Unable to update federation scope of primary email', e)
				}
			})
		},
	},
}
</script>

<style lang="scss" scoped>
	.actions-federation {
		margin: -12px 0 0 8px;
		opacity: 0.4 !important;

		&:hover {
			opacity: 0.8 !important;
		}
	}

	.forced-active {
		background-color: var(--color-primary-light) !important;
		box-shadow: inset 2px 0 var(--color-primary) !important;
	}

	.forced-action {
		&::v-deep p {
			width: 150px !important;
			padding: 8px 0 !important;
			color: var(--color-main-text) !important;
			font-size: 12.8px !important;
			line-height: 1.5em !important;
		}
	}
</style>
