From Coq Require Import ZArith QArith NArith List Bool Lia.
Require Coq.Strings.String Coq.Strings.Ascii.
From Coq Require Uint63 PArray.
Import ListNotations.

Module FCIDUMP.
Import Coq.Strings.String.
Local Open Scope string_scope.



Definition bytes (s : String.string) : list N :=
  map (fun c => N.of_nat (Ascii.nat_of_ascii c)) (String.list_ascii_of_string s).

Local Open Scope N_scope.
Definition m32 (x : N) : N := N.land x 4294967295.
Definition add32 (x y : N) : N := m32 (x + y).
Definition rotr (x n : N) : N := m32 (N.lor (N.shiftr x n) (N.shiftl x (32 - n))).
Definition ch (x y z : N) : N := N.lxor (N.land x y) (N.land (N.lxor x 4294967295) z).
Definition maj (x y z : N) : N := N.lxor (N.lxor (N.land x y) (N.land x z)) (N.land y z).
Definition bsig0 (x : N) : N := N.lxor (N.lxor (rotr x 2) (rotr x 13)) (rotr x 22).
Definition bsig1 (x : N) : N := N.lxor (N.lxor (rotr x 6) (rotr x 11)) (rotr x 25).
Definition ssig0 (x : N) : N := N.lxor (N.lxor (rotr x 7) (rotr x 18)) (N.shiftr x 3).
Definition ssig1 (x : N) : N := N.lxor (N.lxor (rotr x 17) (rotr x 19)) (N.shiftr x 10).
Definition is_prime (p : N) : bool :=
  forallb (fun d => negb (N.eqb (p mod N.of_nat d) 0)) (seq 2 (N.to_nat p - 2)).
Definition primes (k : nat) : list N :=
  firstn k (filter is_prime (map N.of_nat (seq 2 400))).
Fixpoint icbrt_bits (b : nat) (n r : N) : N :=
  match b with
  | O => r
  | S b' => let r' := r + 2 ^ N.of_nat b' in
            icbrt_bits b' n (if r' * r' * r' <=? n then r' else r)
  end.
Definition icbrt (n : N) : N := icbrt_bits 40 n 0.
Definition Kc : list N := map (fun p => m32 (icbrt (p * 2 ^ 96))) (primes 64).
Definition H0 : list N := map (fun p => m32 (N.sqrt (p * 2 ^ 64))) (primes 8).


Definition be_bytes (k : nat) (x : N) : list N :=
  map (fun i => N.land (N.shiftr x (8 * N.of_nat (k - 1 - i)%nat)) 255) (seq 0 k).
Definition pad (msg : list N) : list N :=
  let len := List.length msg in
  let z := ((119 - (len mod 64)) mod 64)%nat in
  msg ++ [128] ++ repeat 0 z ++ be_bytes 8 (8 * N.of_nat len).
Fixpoint words (l : list N) : list N :=
  match l with
  | a :: b :: c :: d :: r => (a * 16777216 + b * 65536 + c * 256 + d) :: words r
  | _ => []
  end.
Fixpoint chunks (n : nat) (l : list N) : list (list N) :=
  match n with O => [] | S n' => firstn 16 l :: chunks n' (skipn 16 l) end.
Fixpoint sched (k : nat) (w : list N) : list N :=
  match k with
  | O => w
  | S k' => let t := List.length w in
      sched k' (w ++ [add32 (add32 (ssig1 (nth (t - 2) w 0)) (nth (t - 7) w 0))
                            (add32 (ssig0 (nth (t - 15) w 0)) (nth (t - 16) w 0))])
  end.
Definition round (st : list N) (kw : N * N) : list N :=
  match st with
  | [a; b; c; d; e; f; g; h] =>
      let t1 := add32 (add32 (add32 h (bsig1 e)) (add32 (ch e f g) (fst kw))) (snd kw) in
      let t2 := add32 (bsig0 a) (maj a b c) in
      [add32 t1 t2; a; b; c; add32 d t1; e; f; g]
  | _ => st
  end.
Definition compress (hs : list N) (blk : list N) : list N :=
  let w := sched 48 blk in
  let st := fold_left round (combine Kc w) hs in
  map (fun '(x, y) => add32 x y) (combine hs st).
Definition sha256 (msg : list N) : list N :=
  let p := words (pad msg) in
  fold_left compress (chunks (List.length p / 16) p) H0.

Definition hexc (d : N) : Ascii.ascii := Ascii.ascii_of_N (if d <? 10 then 48 + d else 87 + d).
Definition hex8 (x : N) : list Ascii.ascii :=
  map (fun i => hexc (N.land (N.shiftr x (4 * N.of_nat (7 - i)%nat)) 15)) (seq 0 8).
Definition sha256_hex (msg : list N) : String.string :=
  String.string_of_list_ascii (flat_map hex8 (sha256 msg)).
Close Scope N_scope.




(* ---- parsing ---- *)
Definition sep (c : Ascii.ascii) : bool :=
  let n := Ascii.nat_of_ascii c in
  (Nat.eqb n 32 || Nat.eqb n 10 || Nat.eqb n 9 || Nat.eqb n 13 || Nat.eqb n 44)%bool.
Fixpoint toks (l : list Ascii.ascii) (cur : list Ascii.ascii) : list (list Ascii.ascii) :=
  match l with
  | [] => match cur with [] => [] | _ => [rev cur] end
  | c :: r => if sep c then match cur with [] => toks r [] | _ => rev cur :: toks r [] end
              else toks r (c :: cur)
  end.
Definition digit (c : Ascii.ascii) : option Z :=
  let n := Ascii.nat_of_ascii c in
  if (Nat.leb 48 n && Nat.leb n 57)%bool then Some (Z.of_nat (n - 48)) else None.
Fixpoint digits (l : list Ascii.ascii) (acc : Z) (k : nat) : option (Z * nat) :=
  match l with
  | [] => Some (acc, k)
  | c :: r => match digit c with Some d => digits r (10 * acc + d)%Z (S k) | None => None end
  end.
Definition pnat (l : list Ascii.ascii) : option nat :=
  match l with [] => None | _ => match digits l 0 0 with Some (z, _) => Some (Z.to_nat z) | None => None end end.
Fixpoint split_dot (l : list Ascii.ascii) : list Ascii.ascii * option (list Ascii.ascii) :=
  match l with
  | [] => ([], None)
  | c :: r => if Nat.eqb (Ascii.nat_of_ascii c) 46 then ([], Some r)
              else let '(a, b) := split_dot r in (c :: a, b)
  end.
Definition pdec (l : list Ascii.ascii) : option Q :=
  let '(sg, body) := match l with
                     | c :: r => if Nat.eqb (Ascii.nat_of_ascii c) 45 then ((-1)%Z, r) else (1%Z, l)
                     | [] => (1%Z, [])
                     end in
  let '(ip, fp) := split_dot body in
  match ip, digits ip 0 0, match fp with None => Some (0%Z, O) | Some f => digits f 0 0 end with
  | _ :: _, Some (i, _), Some (f, k) =>
      Some (Qmake (sg * (i * 10 ^ Z.of_nat k + f))%Z (Z.to_pos (10 ^ Z.of_nat k)))
  | _, _, _ => None
  end.
(* Numbers may carry an exponent, as in -2.36914280092e-05 or 1.5E+02.
   pnum splits at the first e/E, reads the mantissa with pdec and the exponent
   with pint, and scales the exact rational by the power of ten. *)
Fixpoint split_exp (l : list Ascii.ascii) : list Ascii.ascii * option (list Ascii.ascii) :=
  match l with
  | [] => ([], None)
  | c :: r => let n := Ascii.nat_of_ascii c in
              if (Nat.eqb n 101 || Nat.eqb n 69)%bool then ([], Some r)
              else let '(a, b) := split_exp r in (c :: a, b)
  end.
Definition pint (l : list Ascii.ascii) : option Z :=
  let '(sg, body) := match l with
                     | c :: r => if Nat.eqb (Ascii.nat_of_ascii c) 45 then ((-1)%Z, r)
                                 else if Nat.eqb (Ascii.nat_of_ascii c) 43 then (1%Z, r)
                                 else (1%Z, l)
                     | [] => (1%Z, [])
                     end in
  match body with
  | [] => None
  | _ => match digits body 0 0 with Some (z, _) => Some (sg * z)%Z | None => None end
  end.
Definition pnum (l : list Ascii.ascii) : option Q :=
  let '(m, e) := split_exp l in
  match pdec m, e with
  | Some x, None => Some x
  | Some x, Some el =>
      match pint el with
      | Some z => if Z.leb 0 z then Some (Qmake (Qnum x * 10 ^ z) (Qden x))
                  else Some (Qmake (Qnum x) (Qden x * Z.to_pos (10 ^ (- z))))
      | None => None
      end
  | _, _ => None
  end.
Definition str (s : String.string) : list Ascii.ascii := String.list_ascii_of_string s.
Fixpoint prefix (p l : list Ascii.ascii) : option (list Ascii.ascii) :=
  match p, l with
  | [], _ => Some l
  | a :: p', b :: l' => if Ascii.eqb a b then prefix p' l' else None
  | _, _ => None
  end.
Fixpoint key (k : String.string) (ts : list (list Ascii.ascii)) : option (list Ascii.ascii) :=
  match ts with
  | [] => None
  | t :: r => match prefix (str k) t with
              | Some [] => match r with v :: _ => Some v | [] => None end
              | Some v => Some v
              | None => key k r
              end
  end.
Fixpoint after_end (ts : list (list Ascii.ascii)) : list (list Ascii.ascii) :=
  match ts with
  | [] => []
  | t :: r => match prefix (str "&END") t with Some [] => r | _ => after_end r end
  end.
Fixpoint entries (fuel : nat) (ts : list (list Ascii.ascii)) : option (list (Q * nat * nat * nat * nat)) :=
  match fuel with O => None | S f =>
  match ts with
  | [] => Some []
  | v :: i :: j :: k :: l :: r =>
      match pnum v, pnat i, pnat j, pnat k, pnat l, entries f r with
      | Some x, Some i', Some j', Some k', Some l', Some es => Some ((x, i', j', k', l') :: es)
      | _, _, _, _, _, _ => None
      end
  | _ => None
  end end.

Record FCI := { norb : nat; nelec : nat; ms2 : nat; ints : list (Q * nat * nat * nat * nat) }.

Definition parse (l : list Ascii.ascii) : option FCI :=
  let ts := toks l [] in
  match key "NORB=" ts, key "NELEC=" ts, key "MS2=" ts with
  | Some a, Some b, Some c =>
      match pnat a, pnat b, pnat c, entries (List.length ts) (after_end ts) with
      | Some n, Some e, Some m, Some es => Some {| norb := n; nelec := e; ms2 := m; ints := es |}
      | _, _, _, _ => None
      end
  | _, _, _ => None
  end.

Definition empty : FCI := {| norb := 0; nelec := 0; ms2 := 0; ints := [] |}.


Definition eq4 (a b : nat * nat * nat * nat) : bool :=
  let '(a1, a2, a3, a4) := a in let '(b1, b2, b3, b4) := b in
  (Nat.eqb a1 b1 && Nat.eqb a2 b2 && Nat.eqb a3 b3 && Nat.eqb a4 b4)%bool.
Definition lookup (I : FCI) (ok : nat * nat * nat * nat -> bool) : Q :=
  fold_right (fun '(x, i, j, k, l) acc => if ok (i, j, k, l) then x else acc) 0%Q (ints I).
Definition hcore (I : FCI) (p q : nat) : Q :=
  lookup I (fun t => (eq4 t (S p, S q, O, O) || eq4 t (S q, S p, O, O))%bool).
Definition eri (I : FCI) (p q r s : nat) : Q :=
  let p := S p in let q := S q in let r := S r in let s := S s in
  lookup I (fun t => existsb (eq4 t)
    [(p,q,r,s); (q,p,r,s); (p,q,s,r); (q,p,s,r); (r,s,p,q); (s,r,p,q); (r,s,q,p); (s,r,q,p)]).
Definition enuc (I : FCI) : Q := lookup I (fun t => eq4 t (O, O, O, O)).


Local Open Scope N_scope.
Fixpoint split64 (fuel : nat) (l : list N) : list (list N) :=
  match fuel with
  | O => []
  | S f => match l with [] => [] | _ => firstn 64 l :: split64 f (skipn 64 l) end
  end.
Definition absorb (st : list N) (l : list N) : list N :=
  fold_left (fun s b => compress s (words b)) (split64 (List.length l) l) st.
Definition pad_final (tail : list N) (total : nat) : list N :=
  let z := ((119 - (total mod 64)) mod 64)%nat in
  (tail ++ [128] ++ repeat 0 z ++ be_bytes 8 (8 * N.of_nat total))%list.
Definition hex_of (st : list N) : String.string :=
  String.string_of_list_ascii (flat_map hex8 st).
Definition total_len (full : list (list N)) (tail : list N) : nat :=
  fold_left (fun a c => (a + List.length c)%nat) full (List.length tail).
Definition sha256_stream (full : list (list N)) (tail : list N) : String.string :=
  hex_of (absorb (fold_left absorb full H0) (pad_final tail (total_len full tail))).
Close Scope N_scope.

Definition cell (arr : PArray.array Uint63.int) (n : nat) : Z :=
  Uint63.to_Z (PArray.get arr (Uint63.of_Z (Z.of_nat n))).
Definition bytes7 (x : Z) : list N :=
  map (fun q => Z.to_N (Z.land (Z.shiftr x (8 * q)) 255)) [0; 1; 2; 3; 4; 5; 6]%Z.
Definition unpack (arr : PArray.array Uint63.int) (len nbytes : nat) : list N :=
  firstn nbytes (flat_map (fun i => bytes7 (cell arr i)) (seq 0 len)).
Definition to_ascii (l : list N) : list Ascii.ascii := map Ascii.ascii_of_N l.
End FCIDUMP.

(* Byte count of an unpacked chunk, proven once for every chunk:
   each 63-bit integer unpacks to 7 bytes, so keeping the first nbytes of
   7*len bytes leaves exactly nbytes whenever nbytes <= 7*len. *)
Module FCIDUMP_unpack.
Import FCIDUMP.
Lemma flat_map_bytes7_length : forall arr l,
  List.length (flat_map (fun i => bytes7 (cell arr i)) l) = (7 * List.length l)%nat.
Proof.
  intros arr l. induction l as [|i r IH]. reflexivity.
  cbn [flat_map]. rewrite app_length, IH. unfold bytes7. rewrite map_length. cbn [List.length]. Lia.lia.
Qed.
Lemma unpack_length : forall arr len nbytes,
  Nat.leb nbytes (7 * len) = true -> List.length (unpack arr len nbytes) = nbytes.
Proof.
  intros arr len nbytes H. apply Nat.leb_le in H. unfold unpack.
  rewrite firstn_length, flat_map_bytes7_length, seq_length. Lia.lia.
Qed.
End FCIDUMP_unpack.
