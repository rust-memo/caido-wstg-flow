import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import "./styles/wstg.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);
  app.use(SDKPlugin, sdk);
  const root = document.createElement("div");
  Object.assign(root.style, { height: "100%", width: "100%" });
  root.id = "plugin--caido-wstg-flow";
  app.mount(root);
  sdk.navigation.addPage("/wstg-flow", { body: root });
  sdk.sidebar.registerItem("WSTG Flow", "/wstg-flow");
};
