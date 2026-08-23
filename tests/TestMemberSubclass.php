<?php

namespace Atwx\SilverGateApi\Tests;

use SilverStripe\Dev\TestOnly;
use SilverStripe\Security\Member;

class TestMemberSubclass extends Member implements TestOnly
{
    private static string $table_name = 'GateApiTestMemberSubclass';
}
