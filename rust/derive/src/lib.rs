/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{self, parse_macro_input, DeriveInput};

#[proc_macro_derive(AppLayerEvent, attributes(event))]
pub fn derive_app_layer_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let mut fields = Vec::new();
    let mut vals = Vec::new();
    let mut cstrings = Vec::new();
    let mut names = Vec::new();

    match input.data {
        syn::Data::Enum(ref data) => {
            let mut count: usize = 0;
            for v in &data.variants {
                fields.push(v.ident.clone());
                for a in &v.attrs {
                    let y = a.parse_meta().unwrap();
                    match y {
                        syn::Meta::List(list) => {
                            for n in list.nested {
                                match n {
                                    syn::NestedMeta::Meta(m) => match m {
                                        syn::Meta::NameValue(nv) => match nv.lit {
                                            syn::Lit::Str(s) => {
                                                if let Some(ident) = nv.path.get_ident() {
                                                    match ident.to_string().as_ref() {
                                                        "name" => {
                                                            cstrings
                                                                .push(format!("{}\0", s.value()));
                                                            names.push(s.value());
                                                        }
                                                        _ => unimplemented!(),
                                                    }
                                                }
                                            }
                                            syn::Lit::Int(i) => {
                                                let i = i
                                                    .base10_parse::<u32>()
                                                    .expect("integer expected");
                                                if let Some(ident) = nv.path.get_ident() {
                                                    match ident.to_string().as_ref() {
                                                        "id" => {
                                                            vals.push(i);
                                                        }
                                                        _ => unimplemented!(),
                                                    }
                                                }
                                            }
                                            _ => unimplemented!(),
                                        },
                                        _ => unimplemented!(),
                                    },
                                    _ => unimplemented!(),
                                }
                            }
                        }
                        _ => unimplemented!(),
                    }
                }

                if vals.len() == count {
                    panic!("id required for {}", v.ident);
                }

                if cstrings.len() == count {
                    panic!("name required for {}", v.ident);
                }

                count += 1;
            }
        }
        _ => unimplemented!(),
    }

    let expanded = quote! {
        impl #name {
            pub fn from_id(id: u32) -> Option<#name> {
                match id {
                    #( #vals => Some(#name::#fields) ,)*
                    _ => None,
                }
            }

            pub fn to_cstring(&self) -> &str {
                match *self {
                    #( #name::#fields => #cstrings ,)*
                }
            }

            pub fn from_string(s: &str) -> Option<#name> {
                match s {
                    #( #names => Some(#name::#fields) ,)*
                    _ => None
                }
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}
