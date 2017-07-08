// an implementation of Telegram's MTProto in Rust
// Copyright (C) 2017  Keyboard Fire <andy@keyboardfire.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate mtprs;
use mtprs::Mtprs;

fn main() {
    let mut client = Mtprs::new();
    client.auth().unwrap();
}
