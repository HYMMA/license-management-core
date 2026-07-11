<?php

declare(strict_types=1);

namespace Hymma\Licensing;

/**
 * Signed-license wire formats the server can emit.
 */
enum SignedFormat: int
{
    case Rs256 = 1;
    case Es256 = 2;
    case EdDsa = 3;
}
