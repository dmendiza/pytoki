import click

import pkcs11


@click.group()
@click.option("--debug/--no-debug", default=False)
@click.option(
    "--lib", required=True, type=click.Path(exists=True, dir_okay=False)
)
@click.pass_context
def cli(ctx, debug, lib):
    ctx.ensure_object(dict)

    ctx.obj["DEBUG"] = debug


@cli.command()
def slots():
    #    count_pt = _ffi.new("CK_ULONG_PTR")
    #    rv = cryptoki.C_GetSlotList(CK_FALSE, _ffi.NULL, count_pt)
    #    error_check(rv)
    #    count = count_pt[0]
    #
    #    if count > 0:
    #        # slots = _ffi.new('CK_SLOT_ID[{}]'.format(count))
    #        slots_ptr = _ffi.new("CK_SLOT_ID_PTR")
    #        rv = cryptoki.C_GetSlotList(CK_FALSE, slots_ptr, count_pt)
    #        error_check(rv)
    #        click.echo("ID:{}".format(slots_ptr[0]))
    #
    #        slot_info = _ffi.new("CK_SLOT_INFO_PTR")
    #        rv = cryptoki.C_GetSlotInfo(slots_ptr[0], slot_info)
    #        error_check(rv)
    #        click.echo(_ffi.string(slot_info.slotDescription))
    #        click.echo(_ffi.string(slot_info.manufacturerID))
    #        click.echo(
    #            "HW: {}.{}".format(
    #                slot_info.hardwareVersion.major, slot_info.hardwareVersion.minor
    #            )
    #        )
    #        click.echo(
    #            "FW: {}.{}".format(
    #                slot_info.firmwareVersion.major, slot_info.firmwareVersion.minor
    #            )
    #        )
    #
    #    click.echo(count)
    #    rv = cryptoki.C_Finalize(_ffi.NULL)
    #    error_check(rv)
    pass


@cli.command()
def mechanisms():
    #    count_pt = _ffi.new("CK_ULONG_PTR")
    #    rv = cryptoki.C_GetSlotList(CK_FALSE, _ffi.NULL, count_pt)
    #    error_check(rv)
    #    count = count_pt[0]
    #
    #    if count > 0:
    #        slots_ptr = _ffi.new("CK_SLOT_ID_PTR")
    #        rv = cryptoki.C_GetSlotList(CK_FALSE, slots_ptr, count_pt)
    #        error_check(rv)
    #        slot_id = slots_ptr[0]
    #
    #        session_ptr = _ffi.new("CK_SESSION_HANDLE_PTR")
    #        rv = cryptoki.C_OpenSession(
    #            slot_id,
    #            CKF_RW_SESSION | CKF_SERIAL_SESSION,
    #            _ffi.NULL,
    #            _ffi.NULL,
    #            session_ptr,
    #        )
    #        error_check(rv)
    #        session = session_ptr[0]
    #
    #        info_ptr = _ffi.new("CK_SESSION_INFO_PTR")
    #
    #        rv = cryptoki.C_GetSessionInfo(session, info_ptr)
    #        error_check(rv)
    #        click.echo(_SESSION_STATES[info_ptr.state])
    #
    #        # pin = _ffi.new('CK_UTF8CHAR[]', [52, 51, 49, 48, 54, 49])
    #        # TODO: Get this pin from env
    #        pin = b"1234"
    #
    #        rv = cryptoki.C_Login(session, CKU_USER, pin, len(pin))
    #        error_check(rv)
    #
    #        rv = cryptoki.C_GetSessionInfo(session, info_ptr)
    #        error_check(rv)
    #        click.echo(_SESSION_STATES[info_ptr.state])
    #
    #        # rsa_type = _ffi.new('CK_KEY_TYPE *')
    #        # rsa_type[0] = CKK_RSA
    #        # template = _ffi.new('CK_ATTRIBUTE[]', 1)
    #        # template[0].type = CKA_KEY_TYPE
    #        # template[0].pValue = rsa_type
    #        # template[0].ulValueLen = _ffi.sizeof(rsa_type)
    #
    #        # rv = cryptoki.C_FindObjectsInit(session,
    #        #                                template,
    #        #                                0)
    #        # error_check(rv)
    #
    #        # obj_handle = _ffi.new('CK_OBJECT_HANDLE_PTR')
    #        # results_ptr = _ffi.new('CK_ULONG_PTR')
    #        # rv = cryptoki.C_FindObjects(session,
    #        #                            obj_handle,
    #        #                            1,
    #        #                            results_ptr)
    #        # error_check(rv)
    #        # results = results_ptr[0]
    #        # click.echo(results)
    #
    #        # rv = cryptoki.C_FindObjectsFinal(session)
    #        # error_check(rv)
    #
    #        ct_ptr = _ffi.new("CK_ULONG_PTR")
    #        rv = cryptoki.C_GetMechanismList(slot_id, _ffi.NULL, ct_ptr)
    #        error_check(rv)
    #        ct = ct_ptr[0]
    #        click.echo("{} Mechanisms Supported:".format(ct))
    #
    #        mechanisms = _ffi.new("CK_MECHANISM_TYPE[]", ct)
    #        rv = cryptoki.C_GetMechanismList(slot_id, mechanisms, ct_ptr)
    #        error_check(rv)
    #
    #        for x in range(ct):
    #            click.echo(_MECHANISMS[(mechanisms[x])])
    #
    #        rv = cryptoki.C_CloseSession(session)
    #        error_check(rv)
    #        rv = cryptoki.C_Finalize(_ffi.NULL)
    #        error_check(rv)
    pass


@cli.command()
def version():
    #    info = _ffi.new("CK_INFO_PTR")
    #    rv = cryptoki.C_GetInfo(info)
    #    error_check(rv)
    #    click.echo(_ffi.string(info.manufacturerID))
    #    click.echo(_ffi.string(info.libraryDescription))
    #    click.echo(
    #        "Library Version {}.{}".format(
    #            info.libraryVersion.major, info.libraryVersion.minor
    #        )
    #    )
    #    click.echo(
    #        "Cryptoki (PKCS#11) Version {}.{}".format(
    #            info.cryptokiVersion.major, info.cryptokiVersion.minor
    #        )
    #    )
    #    rv = cryptoki.C_Finalize(_ffi.NULL)
    #    error_check(rv)
    pass


if __name__ == "__main__":
    cli(auto_envvar_prefix="PYTOKI")
