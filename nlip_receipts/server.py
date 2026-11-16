"""FastAPI NLIP Server integration (`nlip_server`) with Type-3 Security Extension support."""

from __future__ import annotations

from fastapi import FastAPI
from nlip_sdk.nlip import AllowedFormats, NLIP_Message, NLIP_SubMessage, ReservedTokens
from nlip_server import server as nlip_srv

from .gate import Type3ReceiptExtension
from .schemas import Type3Decision, pack_decision_message


class ReceiptNLIPSession(nlip_srv.NLIP_Session):
    """NLIP_Session that routes tool-boundary requests through `Type3ReceiptExtension`
    and answers ECMA-430 §5.1.1/§6.3 `control` messages with ECMA-434 profile metadata.
    """

    def __init__(self, extension: Type3ReceiptExtension):
        self.extension = extension
        self.set_correlator()

    async def execute(self, msg: NLIP_Message) -> NLIP_Message:
        # ECMA-430 §5.1.1 & §6.3: Control messages query endpoint policy and ECMA-434 profile
        if msg.is_control_msg():
            return NLIP_Message(
                messagetype=ReservedTokens.control,
                format=AllowedFormats.text,
                subformat="english",
                content=(
                    "NLIP Type-3 Security Extension active. Conforms to ECMA-430 and ECMA-434 "
                    "(SCOs 7.1.3, 7.2.2, 7.2.3, 7.2.4, 7.3.2, and proposed SCO 7.3.4)."
                ),
                submessages=[
                    NLIP_SubMessage(
                        format=AllowedFormats.structured,
                        subformat="json",
                        label="ecma434.profile",
                        content={
                            "standard": "ECMA-434:2025",
                            "extension_type": "Type-3 (Tool/Execution Boundary)",
                            "implemented_scos": [
                                "7.1.3",
                                "7.2.2",
                                "7.2.3",
                                "7.2.4",
                                "7.2.7",
                                "7.3.2",
                                "7.3.4-proposed",
                            ],
                            "issuer_id": self.extension.ledger.issuer_id(),
                            "ethical_disclosure": "ETHICS.md",
                            "security_disclosure": "SECURITY.md",
                        },
                    )
                ],
            )

        try:
            return self.extension.handle_nlip_message(msg)
        except ValueError as exc:
            decision = Type3Decision(
                action="deny",
                reason_code="MALFORMED_NLIP_TOOL_CALL",
                message=f"[NLIP-SE Type-3] Denied: {exc}",
                sco_refs=["ECMA-434:7.3.2"],
                operation="unknown",
                repo_id="unknown",
                caller_id="anonymous",
            )
            return pack_decision_message(decision)


class ReceiptNLIPApplication(nlip_srv. SafeApplication):
    """`nlip_server.SafeApplication` hosting the Type-3 Security Extension."""

    def __init__(self, extension: Type3ReceiptExtension):
        self.extension = extension

    def create_session(self) -> nlip_srv.NLIP_Session:
        return ReceiptNLIPSession(self.extension)


def create_nlip_receipt_server(extension: Type3ReceiptExtension) -> FastAPI:
    """Create a FastAPI app using `nlip_server.setup_server`."""
    client_app = ReceiptNLIPApplication(extension)
    client_app.session_list = []
    app = nlip_srv.setup_server(client_app)
    app.state.client_app = client_app
    return app
