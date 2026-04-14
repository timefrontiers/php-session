<?php

declare(strict_types=1);

namespace TimeFrontiers;

enum AccessRank: int {
  case GUEST = 0;
  case USER = 1;
  case ANALYST = 2;
  case ADVERTISER = 3;
  case MODERATOR = 4;
  case EDITOR = 5;
  case ADMIN = 6;
  case DEVELOPER = 7;
  case SUPERADMIN = 8;
  case OWNER = 14;
}