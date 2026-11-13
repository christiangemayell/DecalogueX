"""
AUTH-001: an owner check that lets logged-out visitors through.

    where: { id: postId, authorId: session?.user.id }

When nobody is logged in, session?.user.id is undefined, and Prisma (and
Mongoose) skip filters set to undefined, so the check matches everyone's data.
"""

from pathlib import Path

from decaloguex import engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def auth_findings(folder: Path) -> list:
    return [f for f in engine.scan(folder).findings if f.rule_id == "AUTH-001"]


# js-3-nextjs-taxonomy: app/api/posts/[postId]/route.ts
TAXONOMY = """
async function verifyCurrentUserHasAccessToPost(postId: string) {
  const session = await getServerSession(authOptions)
  const count = await db.post.count({
    where: {
      id: postId,
      authorId: session?.user.id,
    },
  })
  return count > 0
}
"""


def test_prisma_owner_check_with_maybe_empty_login(tmp_path):
    write(tmp_path, "route.ts", TAXONOMY)
    found = auth_findings(tmp_path)
    assert len(found) == 1 and found[0].line == 7 and found[0].fix is None
    assert "if (!session)" in found[0].note


def test_mongoose_filter(tmp_path):
    write(tmp_path, "notes.js", "async function get(req, res) {\n"
                                "  const note = await Note.findOne({ _id: req.params.id, owner: req.user?._id });\n"
                                "  res.json(note);\n}\n")
    assert len(auth_findings(tmp_path)) == 1


def test_login_checked_first_is_fine(tmp_path):
    write(tmp_path, "route.ts", """
async function update(postId: string) {
  const session = await getServerSession(authOptions)
  if (!session) {
    return new Response(null, { status: 401 })
  }
  return db.post.update({ where: { id: postId, authorId: session?.user.id }, data: {} })
}
""")
    assert auth_findings(tmp_path) == []


def test_no_question_mark_or_not_a_filter_is_fine(tmp_path):
    write(tmp_path, "route.ts", """
async function list(session) {
  const posts = await db.post.findMany({ where: { authorId: session.user.id } })
  return { name: session?.user.id, posts }
}
""")
    assert auth_findings(tmp_path) == []


def test_not_a_login_value_is_fine(tmp_path):
    write(tmp_path, "route.ts", "const p = await db.post.findFirst({ where: { categoryId: category?.id } })\n")
    assert auth_findings(tmp_path) == []


def test_a_stripe_session_is_not_a_login(tmp_path):
    # js-3-nextjs-taxonomy: app/api/webhooks/stripe/route.ts. "session" is a
    # Stripe Checkout Session (a payment), not the logged-in user.
    write(tmp_path, "route.ts", """
export async function POST(req: Request) {
  const session = event.data.object as Stripe.Checkout.Session
  await db.user.update({ where: { id: session?.metadata?.userId }, data: {} })
}
""")
    assert auth_findings(tmp_path) == []


# --- AUTH-002: anyone logged in can change anyone's data -------------------------------

def auth2(folder: Path) -> list:
    return [f for f in engine.scan(folder).findings if f.rule_id == "AUTH-002"]


def test_django_delete_with_no_owner_check(tmp_path):
    # python-2-django-realworld: conduit/apps/articles/views.py
    write(tmp_path, "views.py", """
class CommentsDestroyAPIView(generics.DestroyAPIView):
    permission_classes = (IsAuthenticatedOrReadOnly,)

    def destroy(self, request, article_slug=None, comment_pk=None):
        try:
            comment = Comment.objects.get(pk=comment_pk)
        except Comment.DoesNotExist:
            raise NotFound('A comment with this ID does not exist.')
        comment.delete()
        return Response(None, status=status.HTTP_204_NO_CONTENT)
""")
    found = auth2(tmp_path)
    assert len(found) == 1 and "comment.author != request.user" in found[0].note


def test_express_delete_by_request_id_with_no_owner_check(tmp_path):
    write(tmp_path, "routes.js", "router.delete('/posts/:id', async (req, res) => {\n"
                                 "  await Post.findByIdAndDelete(req.params.id);\n  res.sendStatus(204);\n});\n")
    assert len(auth2(tmp_path)) == 1


def test_owner_checked_in_the_function_is_fine(tmp_path):
    # python-3-fastapi-template style
    write(tmp_path, "items.py", """
def delete_item(session, current_user, id):
    item = session.query.get(id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403)
    item.delete()
""")
    write(tmp_path, "routes.js", "router.delete('/posts/:id', async (req, res) => {\n"
                                 "  const post = await Post.findById(req.params.id);\n"
                                 "  if (post.author.toString() !== req.user.id) return res.sendStatus(403);\n"
                                 "  await post.deleteOne();\n});\n")
    assert auth2(tmp_path) == []


def test_owner_permission_class_and_admin_pages_are_fine(tmp_path):
    write(tmp_path, "views.py", """
class CommentView(generics.DestroyAPIView):
    permission_classes = (IsOwnerOrReadOnly,)

    def destroy(self, request, pk=None):
        comment = Comment.objects.get(pk=pk)
        comment.delete()
""")
    write(tmp_path, "admin/views.py", "def remove(request, pk):\n    user = User.objects.get(pk=pk)\n    user.delete()\n")
    assert auth2(tmp_path) == []


def test_only_showing_something_is_not_a_change(tmp_path):
    # python-2-django-realworld: profiles/views.py retrieve() only shows the profile.
    write(tmp_path, "views.py", """
class ProfileRetrieveAPIView(RetrieveAPIView):
    def retrieve(self, request, username, *args, **kwargs):
        profile = self.queryset.get(user__username=username)
        serializer = self.serializer_class(profile, context={
            'request': request
        })
        return Response(serializer.data)
""")
    assert auth2(tmp_path) == []


def test_django_update_through_a_serializer_is_a_change(tmp_path):
    # python-2-django-realworld: articles/views.py update()
    write(tmp_path, "views.py", """
class ArticleViewSet(viewsets.ModelViewSet):
    def update(self, request, slug):
        serializer_instance = self.queryset.get(slug=slug)
        serializer = self.serializer_class(
            serializer_instance,
            data=request.data.get('article', {}),
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
""")
    assert len(auth2(tmp_path)) == 1
