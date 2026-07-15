// @vitest-environment happy-dom

import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ConfirmDialog from "./ConfirmDialog.vue";
import PaginationControls from "./PaginationControls.vue";

describe("shared UI controls", () => {
  it("emits an accessible confirmation decision", async () => {
    const wrapper = mount(ConfirmDialog, {
      props: {
        open: true,
        title: "Delete candidates",
        message: "This keeps confirmed findings.",
        confirmLabel: "Delete",
        danger: true,
      },
    });
    expect(wrapper.get('[role="alertdialog"]').attributes("aria-modal")).toBe(
      "true",
    );
    await wrapper.get("button.danger").trigger("click");
    expect(wrapper.emitted("confirm")).toHaveLength(1);
    await wrapper.get("button:not(.danger)").trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(1);
    await wrapper.get(".wstg-dialog-backdrop").trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(2);
    await wrapper.setProps({ open: false });
    expect(wrapper.find('[role="alertdialog"]').exists()).toBe(false);
  });

  it("emits bounded page offsets", async () => {
    const wrapper = mount(PaginationControls, {
      props: { offset: 50, limit: 50, total: 120 },
    });
    const buttons = wrapper.findAll("button");
    await buttons[0]!.trigger("click");
    await buttons[1]!.trigger("click");
    expect(wrapper.emitted("change")).toEqual([[0], [100]]);
    expect(wrapper.text()).toContain("51–100 of 120");
  });
});
