<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/**
 * Why the license server could not be reached — the native hlm_net_failure /
 * the .NET SDK's NetworkFailureReason.
 */
enum NetworkFailure: int
{
    /** No transport failure on the last call. */
    case None = 0;
    /** Failed; the cause could not be determined. */
    case Unknown = 1;
    /** DNS returned no address for the server — typically a company DNS filter. */
    case NameResolution = 2;
    /** The TLS handshake failed — often an HTTPS-inspecting proxy. */
    case SecureConnection = 3;
    /** A web proxy refused or failed the connection, or demanded credentials (407). */
    case Proxy = 4;
    /** The server did not answer in time. */
    case Timeout = 5;
    /** The address was found but the connection was refused or dropped. */
    case Connection = 6;
}
