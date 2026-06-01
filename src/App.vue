<template>
  <v-app theme="dark">
    <v-app-bar flat>
      <v-container class="d-flex align-center">
        <v-avatar class="me-4 ms-4" color="grey-darken-3" size="32">
          <v-icon :icon="mdiConsoleLine"/>
        </v-avatar>
        <a href="" class="me-4 font-weight-bold" style="color: inherit; text-decoration: none">
          Piping SSH
        </a>

        <v-spacer></v-spacer>

        <!-- TODO: manage known hosts -->
        <v-btn @click="keyManagerDialog = !keyManagerDialog" variant="text" :prepend-icon="mdiKey">
          Manage keys
        </v-btn>
        <v-btn :icon="mdiGithub" href="https://github.com/nwtgck/piping-ssh-web" target="_blank"/>
      </v-container>
    </v-app-bar>

    <v-main>
      <v-container v-if="!connecting">
        <v-row>
          <v-col>
            <v-sheet v-if="!supportsRequestStreams">
              <v-alert color="warning" :icon="mdiAlertCircle" variant="outlined" prominent border="top" style="margin-bottom: 2rem;">
                <template v-slot:text>
                  Sorry, this browser is not supported.<br>
                  Use Google Chrome 105 or higher.<br>
                  You can also use Microsoft Edge or other Chromium-based browsers.
                </template>
              </v-alert>
            </v-sheet>

            <v-sheet min-height="70vh" rounded="lg" style="padding: 1rem">
              <v-form @submit.prevent="connect" v-model="formValid" :disabled="!supportsRequestStreams">
                <v-row>
                  <v-col>
                    <v-text-field label="SSH server host" v-model="sshHost" required variant="solo-filled" :rules="createRequiredRules('SSH server host')"></v-text-field>
                  </v-col>
                  <v-col>
                    <v-text-field label="SSH server port" v-model="sshPort" required variant="solo-filled" :rules="createRequiredRules('SSH server port')"></v-text-field>
                  </v-col>
                </v-row>
                <v-text-field label="user name" v-model="username" required variant="solo-filled" :rules="createRequiredRules('user name')"></v-text-field>

                <template v-if="showsMoreOptions">
                  <v-combobox label="Piping Server" v-model="pipingServerUrl" :items="pipingServerUrls" required variant="solo-filled" :rules="createRequiredRules('Piping Server')"></v-combobox>
                  <!-- HTTP header inputs -->
                  <v-row v-for="(header, idx) in editingPipingServerHeaders">
                    <v-col>
                      <v-text-field v-model="header[0]" :label="`HTTP header name ${idx + 1}`" variant="solo-filled"></v-text-field>
                    </v-col>
                    <v-col>
                      <v-text-field v-model="header[1]" :label="`HTTP header value ${idx + 1}`" variant="solo-filled"></v-text-field>
                    </v-col>
                    <v-col>
                      <v-btn :icon="mdiMinus" @click="editingPipingServerHeaders.splice(idx, 1)" variant="text"></v-btn>
                    </v-col>
                  </v-row>
                  <v-btn @click="editingPipingServerHeaders.push(['', ''])" :prepend-icon="mdiPlus" variant="outlined" style="margin-bottom: 1rem; text-transform: none">
                    Add header
                  </v-btn>

                  <v-text-field v-model="editingSshPassword" label="SSH password" :type="showsSshPassword ? 'text' : 'password'" variant="solo-filled">
                    <template v-slot:append-inner>
                      <v-btn @click="showsSshPassword = !showsSshPassword" :icon="showsSshPassword ? mdiEyeOff : mdiEye" variant="text"></v-btn>
                    </template>
                  </v-text-field>
                  <v-checkbox v-model="emptySshPassword" label="Empty SSH password"></v-checkbox>
                  <v-checkbox v-model="includesSshPasswordInFragmentParams" label="Include SSH password in configured URL"></v-checkbox>
                  <v-checkbox v-model="autoConnectForFragmentParams" label="Auto connect for configured URL"></v-checkbox>
                </template>

                <v-btn type="submit" :disabled="!formValid || !supportsRequestStreams" block class="mt-8" color="secondary">
                  Connect
                </v-btn>

                <v-btn @click="showsMoreOptions = !showsMoreOptions" :prepend-icon="showsMoreOptions ? mdiCollapseAll : mdiExpandAll" variant="text" style="margin-top: 1.2rem; text-transform: none">
                  {{ showsMoreOptions ? "Hide options" : "More options" }}
                </v-btn>
              </v-form>

              <v-btn color="grey" @click="setConfiguredUrl()" :prepend-icon="mdiFire" variant="outlined" style="text-transform: none">
                Set configured URL
              </v-btn>
            </v-sheet>
          </v-col>
        </v-row>
      </v-container>

      <PipingSsh v-if="connecting"
                 :piping-server-url="pipingFullUrl"
                 :piping-server-headers="pipingServerHeaders"
                 :default-ssh-password="sshPassword"
                 :username="username"
                 @end="connecting = false"
      />
    </v-main>

    <v-dialog v-model="keyManagerDialog" scrollable width="90vw">
      <v-card>
        <v-card-title class="d-flex">
          <div class="ma-2">Keys</div>
          <v-spacer/>
          <v-btn @click="keyManagerDialog = false" :icon="mdiClose" variant="text"></v-btn>
        </v-card-title>
        <v-divider></v-divider>
        <v-card-text style="min-height: 70vh;">
          <div style="text-align: end; margin-bottom: 1rem;">
            <v-btn @click="newKeyDialog = !newKeyDialog" :prepend-icon="mdiPlus" color="secondary" style="margin-right: 1rem;">
              New
            </v-btn>
            <v-btn @click="generateKeyDialog = !generateKeyDialog" :prepend-icon="mdiAutoFix" color="secondary">
              Generate
            </v-btn>
          </div>
          <KeyManager />
        </v-card-text>
      </v-card>
    </v-dialog>

    <v-dialog v-model="newKeyDialog" width="80vw">
      <v-card>
        <v-card-title class="d-flex">
          <div class="ma-2">New key</div>
          <v-spacer/>
          <v-btn @click="newKeyDialog = false" :icon="mdiClose" variant="text"></v-btn>
        </v-card-title>
        <v-divider></v-divider>
        <v-card-text style="min-height: 70vh;">
          <KeysEditor @save="saveAuthKeySet($event)"/>
        </v-card-text>
      </v-card>
    </v-dialog>

    <v-dialog v-model="generateKeyDialog" width="80vw">
      <v-card>
        <v-card-title class="d-flex">
          <div class="ma-2">Key generator</div>
          <v-spacer/>
          <v-btn @click="generateKeyDialog = false" :icon="mdiClose" variant="text"></v-btn>
        </v-card-title>
        <v-divider></v-divider>
        <v-card-text style="min-height: 70vh;">
          <KeyGenerator @save="saveAuthKeySet($event)"/>
        </v-card-text>
      </v-card>
    </v-dialog>
    <DialogsForGlobal />
  </v-app>
</template>

<script setup lang="ts">
import {computed, onMounted, ref, defineAsyncComponent} from "vue";
import {fragmentParams, getConfiguredUrl} from "@/fragment-params";
import {mdiConsoleLine, mdiKey, mdiPlus, mdiAutoFix, mdiGithub, mdiClose, mdiFire, mdiCollapseAll, mdiExpandAll, mdiMinus, mdiEyeOff, mdiEye, mdiAlertCircle} from "@mdi/js";
import {AuthKeySet, storeAuthKeySet} from "@/authKeySets";
import {createRequiredRules} from "@/createRequiredRules";
import DialogsForGlobal from "@/components/Globals/Globals.vue";
import {showSnackbar} from "@/components/Globals/snackbar/global-snackbar";
import {supportsRequestStreamsPromise} from "@/supportsRequestStreamsPromise";
const PipingSsh = defineAsyncComponent(() => import("@/components/PipingSsh.vue"));
const KeyManager = defineAsyncComponent(() => import("@/components/KeyManager.vue"));
const KeysEditor = defineAsyncComponent(() => import("@/components/KeysEditor.vue"));
const KeyGenerator = defineAsyncComponent(() => import("@/components/KeyGenerator.vue"));


const supportsRequestStreams = ref(true /* There are many Chromium-based browser users for now */);
supportsRequestStreamsPromise.then(supports => supportsRequestStreams.value = supports);

const demoBaseUrl = "https://websocket-tcp-proxy.navigaid.workers.dev/"
const pipingServerUrl = ref<string>(fragmentParams.pipingServerUrl() ?? demoBaseUrl);
const pipingServerUrls = ref<string[]>([
  demoBaseUrl,
]);
const editingPipingServerHeaders = ref<Array<[string, string]>>(fragmentParams.pipingServerHeaders() ?? []);
const pipingServerHeaders = computed<Array<[string, string]>>(() => {
  return editingPipingServerHeaders.value.filter(([name,value]) => name !== "");
});
const sshHost = ref<string>(fragmentParams.sshHost() ?? "terminal.shop");
const sshPort = ref<string>(fragmentParams.sshPort() ?? "22");
const username = ref<string>(fragmentParams.sshUsername() ?? "");

const editingSshPassword = ref<string>(fragmentParams.sshPassword() ?? "");
const showsSshPassword = ref(false);
const emptySshPassword = ref<boolean>(fragmentParams.sshPassword() === "");
const sshPassword = computed<string | undefined>(() => {
  if (editingSshPassword.value === "" && !emptySshPassword.value) {
    return undefined;
  }
  return editingSshPassword.value;
});

const includesSshPasswordInFragmentParams = ref<boolean>(fragmentParams.sshPassword() !== undefined);
const autoConnectForFragmentParams = ref<boolean>(fragmentParams.autoConnect() ?? false);

const pipingFullUrl = computed<string>(() => {
  return `${pipingServerUrl.value}${sshHost.value}:${sshPort.value}`;
});

const formValid = ref(false);
const connecting = ref<boolean>(false);

function connect() {
  connecting.value = true;
}

const showsMoreOptions = ref(false);
const keyManagerDialog = ref(false);
const newKeyDialog = ref(false);
const generateKeyDialog = ref(false);

onMounted(() => {
  if (fragmentParams.autoConnect()) {
    connect();
  }
  window.addEventListener('load', () => {
    preloadForUserExperience();
  });
});

function preloadForUserExperience() {
  import("@xterm/xterm");
  import("@xterm/addon-fit");
  import("@/components/PipingSsh.vue");
  import("clipboard-copy");
  import("@/components/KeyManager.vue");
  import("@/components/KeysEditor.vue");
  import("@/components/KeyGenerator.vue");
}

async function saveAuthKeySet(authKeySet: AuthKeySet) {
  newKeyDialog.value = false;
  generateKeyDialog.value = false;
  await storeAuthKeySet(authKeySet);
}

function setConfiguredUrl() {
  location.href = getConfiguredUrl({
    pipingServerUrl: pipingServerUrl.value,
    pipingServerHeaders: pipingServerHeaders.value,
    sshHost: sshHost.value,
    sshPort: sshPort.value,
    sshUsername: username.value,
    sshPassword: includesSshPasswordInFragmentParams.value ? sshPassword.value : undefined,
    autoConnect: autoConnectForFragmentParams.value,
  });
  showSnackbar({
    message: "URL updated",
  });
}
</script>

<style>
#app {
  font-family: "Avenir Next", Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  //text-align: center;
  color: #2c3e50;
  margin-top: 15px;
}
</style>
